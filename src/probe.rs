use std::time::{Duration, Instant};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::convert::TryInto;
use std::num::Wrapping;
use std::collections::{HashMap, BTreeMap};
use anyhow::{Result};
use super::config::{TargetConfig, TargetType};
use afpacket::r#async::RawPacketStream;
use log::{trace, warn};
use async_std::task;
use async_std::future::timeout;
use async_std::channel::{bounded, Receiver, Sender};
use async_std::io::prelude::{WriteExt, ReadExt};
use pnet::packet::arp::{MutableArpPacket, ArpPacket, ArpHardwareTypes, ArpOperations, Arp};
use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket, EtherTypes, Ethernet};
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, Ipv4};
use pnet::packet::ipv6::{MutableIpv6Packet, Ipv6Packet, Ipv6};
use pnet::packet::{icmp, icmpv6,ipv4};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmp::echo_request::IcmpCodes;
use pnet::packet::icmpv6::ndp::{NeighborSolicit, MutableNeighborSolicitPacket, Icmpv6Codes, NdpOption, NdpOptionTypes};
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::util::MacAddr;
use pnet::packet::Packet;
use pnet::util::{checksum, ipv6_checksum};
use futures::future::join_all;
use cached::proc_macro::cached;

#[derive(Debug, Clone, PartialEq)]
struct ArpTarget {
    addr: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq)]
struct IcmpTarget {
    addr: Ipv4Addr,
    sequence_number: u16,
}

#[derive(Debug, Clone, PartialEq)]
struct NdpTarget {
    addr: Ipv6Addr,
}

#[derive(Debug, Clone, PartialEq)]
struct Icmp6Target {
    addr: Ipv6Addr,
    sequence_number: u16,
}

#[derive(Debug, Clone, PartialEq)]
enum Target {
    Arp(ArpTarget),
    Icmp(IcmpTarget),
    Ndp(NdpTarget),
    Icmp6(Icmp6Target),
}

#[derive(Debug, Clone)]
enum ResponseData {
    Arp {
        l2addr: MacAddr,
    },
    Icmp,
    Ndp {
        l2addr: MacAddr,
    },
    Icmp6,
}

fn get_mac(iface: &str) -> Result<MacAddr> {
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .expect(&format!("Network interface {}", iface));

    Ok(interface.mac.unwrap())
}

fn get_stream(iface: &str) -> Result<RawPacketStream> {
    let mut stream = RawPacketStream::new()?;
    stream.bind(&iface)?;

    // sudo tcpdump -p -ni lo -ddd "arp or icmp or icmp6"
    stream.set_bpf_filter(vec![
        // length: 13
        (40, 0, 0, 12),
        (21, 3, 0, 2054),
        (21, 0, 3, 2048),
        (48, 0, 0, 23),
        (21, 0, 1, 1),
        (21, 0, 6, 34525),
        (48, 0, 0, 20),
        (21, 3, 0, 58),
        (21, 0, 3, 44),
        (48, 0, 0, 54),
        (21, 0, 1, 58),
        (6, 0, 0, 262144),
        (6, 0, 0, 0),
    ])?;
    Ok(stream)
}

fn log_rtt(target: Target, value: u64) {
	let mut entry_fields = BTreeMap::<String, String>::new();
	entry_fields.insert("SYSLOG_IDENTIFIER".into(), "sensor-data".into());

    let (target_type, target_addr) = match target {
        Target::Arp(t) => (TargetType::Arp, IpAddr::V4(t.addr)),
        Target::Icmp(t) => (TargetType::Icmp, IpAddr::V4(t.addr)),
        Target::Ndp(t) => (TargetType::Ndp, IpAddr::V6(t.addr)),
        Target::Icmp6(t) => (TargetType::Icmp6, IpAddr::V6(t.addr)),
    };
	let mut entry = journald::JournalEntry::from_fields(&entry_fields);
	entry.set_message(&format!("ip-monitor={}", serde_json::json!({
        "type": target_type.to_string(),
        "addr": target_addr,
        "rtt_nanos": value,
    })));

	if let Err(e) = journald::writer::submit(&entry) {
		warn!("Error while submitting sensor data to journald: {}", e);
	}
}

fn expect_ipv4_addr(a: IpAddr) -> Ipv4Addr {
    match a {
        IpAddr::V4(v4a) => v4a,
        _ => panic!(),
    }
}

fn expect_ipv6_addr(a: IpAddr) -> Ipv6Addr {
    match a {
        IpAddr::V6(v6a) => v6a,
        _ => panic!(),
    }
}

fn make_arp_request(target: &TargetConfig, dst_mac: Option<MacAddr>) -> Vec<u8> {
    let dst_mac = dst_mac.unwrap_or(MacAddr::zero());
    let source_addr = expect_ipv4_addr(target.source_addr);
    let addr = expect_ipv4_addr(target.addr);
    let source_mac = get_mac(&target.iface).unwrap();

    let arp = Arp {
        hardware_type: ArpHardwareTypes::Ethernet,
        protocol_type: EtherTypes::Ipv4,
        hw_addr_len: 6,
        proto_addr_len: 4,
        operation: ArpOperations::Request,
        sender_hw_addr: source_mac,
        sender_proto_addr: source_addr,
        target_hw_addr: dst_mac,
        target_proto_addr: addr,
        payload: vec![],
    };

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.populate(&arp);

    let ethernet = Ethernet {
        destination: MacAddr::broadcast(),
        source: source_mac,
        ethertype: EtherTypes::Arp,
        payload: arp_packet.packet().to_vec(),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.populate(&ethernet);

    ethernet_packet.packet().to_vec()
}

fn make_icmp_echo_request(target: &TargetConfig, sequence_number: u16, dst_mac: MacAddr) -> Vec<u8> {
    let source_addr = expect_ipv4_addr(target.source_addr);
    let addr = expect_ipv4_addr(target.addr);
    let source_mac = get_mac(&target.iface).unwrap();

    let icmp = icmp::echo_request::EchoRequest {
        icmp_type: IcmpTypes::EchoRequest,
        icmp_code: IcmpCodes::NoCode,
        checksum: 0,
        identifier: 0,
        sequence_number,
        payload: vec![],
    };

    let mut icmp_buffer = [0u8; 40];
    let mut icmp_packet = icmp::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.populate(&icmp);
    icmp_packet.set_checksum(checksum(icmp_packet.packet(), 1));

    let ipv4 = Ipv4 {
        version: 4,
        header_length: 21,
        dscp: 0,
        ecn: 0,
        total_length: 61,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 255,
        next_level_protocol: IpNextHeaderProtocols::Icmp,
        checksum: 0,
        source: source_addr,
        destination: addr,
        options: vec![],
        payload: icmp_packet.packet().to_vec(),
    };

    let mut ipv4_buffer = [0u8; 61];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.populate(&ipv4);
    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable())); // needed?

    let ethernet = Ethernet {
        destination: dst_mac,
        source: source_mac,
        ethertype: EtherTypes::Ipv4,
        payload: ipv4_packet.packet().to_vec(),
    };

    let mut ethernet_buffer = [0u8; 75];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.populate(&ethernet);

    ethernet_packet.packet().to_vec()
}

fn solicited_node_addr(ip: Ipv6Addr) -> Ipv6Addr {
    let mut base = "ff02::1:ff00:0".parse::<Ipv6Addr>().unwrap().octets();
    base[13] = ip.octets()[13];
    base[14] = ip.octets()[14];
    base[15] = ip.octets()[15];
    base.into()
}

fn make_ndp_request(target: &TargetConfig, dst_mac: Option<MacAddr>) -> Vec<u8> {
    let source_addr = expect_ipv6_addr(target.source_addr);
    let addr = expect_ipv6_addr(target.addr);
    let source_mac = get_mac(&target.iface).unwrap();
    let solicited_node_addr = solicited_node_addr(addr);
    let o = solicited_node_addr.octets();
    let dst_mac = dst_mac.unwrap_or_else(|| {
        [0x33, 0x33, o[12], o[13], o[14], o[15]].into()
    });

    let icmp = NeighborSolicit {
        icmpv6_type: Icmpv6Types::NeighborSolicit,
        icmpv6_code: Icmpv6Codes::NoCode,
        checksum: 0,
        reserved: 0,
        target_addr: addr,
        options: vec![
            NdpOption {
                option_type: NdpOptionTypes::SourceLLAddr,
                length: 1,
                data: source_mac.octets().into(),
            },
        ],
        payload: vec![],
    };

    let mut icmp_buffer = [0u8; 32];
    let mut icmp_packet = MutableNeighborSolicitPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.populate(&icmp);
    icmp_packet.set_checksum(ipv6_checksum(icmp_packet.packet(), 1, &[], &source_addr, &solicited_node_addr, IpNextHeaderProtocols::Icmpv6));

    let ipv6 = Ipv6 {
        version: 6,
        traffic_class: 0,
        flow_label: 0,
        payload_length: 32,
        next_header: IpNextHeaderProtocols::Icmpv6,
        hop_limit: 255,
        source: source_addr,
        destination: solicited_node_addr,
        payload: icmp_packet.packet().to_vec(),
    };

    let mut ipv6_buffer = [0u8; 72];
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
    ipv6_packet.populate(&ipv6);

    let ethernet = Ethernet {
        destination: dst_mac,
        source: source_mac,
        ethertype: EtherTypes::Ipv6,
        payload: ipv6_packet.packet().to_vec(),
    };

    let mut ethernet_buffer = [0u8; 86];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.populate(&ethernet);

    ethernet_packet.packet().to_vec()
}

fn make_icmp6_echo_request(target: &TargetConfig, sequence_number: u16, dst_mac: MacAddr) -> Vec<u8> {
    let source_addr = expect_ipv6_addr(target.source_addr);
    let addr = expect_ipv6_addr(target.addr);
    let source_mac = get_mac(&target.iface).unwrap();

    let icmp = icmpv6::echo_request::EchoRequest {
        icmpv6_type: Icmpv6Types::EchoRequest,
        icmpv6_code: Icmpv6Codes::NoCode,
        checksum: 0,
        identifier: 0,
        sequence_number,
        payload: vec![],
    };

    let mut icmp_buffer = [0u8; 32];
    let mut icmp_packet = icmpv6::echo_request::MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.populate(&icmp);
    icmp_packet.set_checksum(ipv6_checksum(icmp_packet.packet(), 1, &[], &source_addr, &addr, IpNextHeaderProtocols::Icmpv6));

    let ipv6 = Ipv6 {
        version: 6,
        traffic_class: 0,
        flow_label: 0,
        payload_length: 32,
        next_header: IpNextHeaderProtocols::Icmpv6,
        hop_limit: 255,
        source: source_addr,
        destination: addr,
        payload: icmp_packet.packet().to_vec(),
    };

    let mut ipv6_buffer = [0u8; 72];
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();
    ipv6_packet.populate(&ipv6);

    let ethernet = Ethernet {
        destination: dst_mac,
        source: source_mac,
        ethertype: EtherTypes::Ipv6,
        payload: ipv6_packet.packet().to_vec(),
    };

    let mut ethernet_buffer = [0u8; 86];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.populate(&ethernet);

    ethernet_packet.packet().to_vec()
}

#[derive(Debug)]
pub struct Probe {
    targets: Vec<TargetConfig>,
}

struct TargetTask {
    incoming_stream: Receiver<(Instant, Target, ResponseData)>,
    target: TargetConfig,
    stream: RawPacketStream,
}

#[cached(time = 60, key = "TargetConfig", convert = r#"{ task.target.clone() }"#, result = true)]
async fn arp_query(task: &mut TargetTask) -> Result<MacAddr> {
    let req_timeout = Duration::from_secs(1000);
    let sent = Instant::now();
    let request = make_arp_request(&task.target, None);
    task.stream.write(&request).await.unwrap();
    let target = Target::Arp(ArpTarget {
        addr: expect_ipv4_addr(task.target.addr.clone())
    });
    let resp_fut = task.get_response(&target, sent);
    match timeout(req_timeout, resp_fut).await {
        Ok((_duration, response_data)) => {
            if let ResponseData::Arp { l2addr } = response_data {
                trace!("arp query for {:?} was answered with {}", target, l2addr);
                Ok(l2addr)
            } else {
                unreachable!();
            }
        },
        Err(err) => {
            warn!("arp query for {:?} timed out", target);
            Err(err)?
        },
    }
}

#[cached(time = 60, key = "TargetConfig", convert = r#"{ task.target.clone() }"#, result = true)]
async fn ndp_query(task: &mut TargetTask) -> Result<MacAddr> {
    let req_timeout = Duration::from_secs(1000);
    let sent = Instant::now();
    let request = make_ndp_request(&task.target, None);
    task.stream.write(&request).await.unwrap();
    let target = Target::Ndp(NdpTarget {
        addr: expect_ipv6_addr(task.target.addr.clone())
    });
    let resp_fut = task.get_response(&target, sent);
    match timeout(req_timeout, resp_fut).await {
        Ok((_duration, response_data)) => {
            if let ResponseData::Ndp { l2addr } = response_data {
                trace!("ndp query for {:?} was answered with {}", target, l2addr);
                Ok(l2addr)
            } else {
                unreachable!();
            }
        },
        Err(err) => {
            warn!("ndp query for {:?} timed out", target);
            Err(err)?
        },
    }
}

impl TargetTask {
    async fn get_response(&mut self, filter_target: &Target, sent: Instant) -> (Duration, ResponseData) {
        loop {
            let (received_time, target, response_data) = self.incoming_stream.recv().await.unwrap();
            if *filter_target != target { continue; }
            match received_time.checked_duration_since(sent) {
                None => continue,
                Some(duration) => break (duration, response_data),
            }
        }
    }

    async fn run(mut self) -> Result<()> {
        let mut sequence_number = Wrapping(1);

        loop {
            let req_interval = Duration::from_millis(1000); // also timeout

            let (request, id) = match self.target.r#type {
                TargetType::Arp => {
                    let dst_mac = arp_query(&mut self).await?;
                    (
                        make_arp_request(&self.target, Some(dst_mac)),
                        Target::Arp(ArpTarget {
                            addr: expect_ipv4_addr(self.target.addr.clone())
                        })
                    )
                },
                TargetType::Icmp => {
                    let dst_mac = arp_query(&mut self).await?;
                    (
                        make_icmp_echo_request(&self.target, sequence_number.0, dst_mac),
                        Target::Icmp(IcmpTarget {
                            addr: expect_ipv4_addr(self.target.addr.clone()),
                            sequence_number: sequence_number.0
                        })
                    )
                },
                TargetType::Ndp => {
                    let dst_mac = ndp_query(&mut self).await?;
                    (
                        make_ndp_request(&self.target, Some(dst_mac)),
                        Target::Ndp(NdpTarget {
                            addr: expect_ipv6_addr(self.target.addr.clone())
                        })
                    )
                },
                TargetType::Icmp6 => {
                    let dst_mac = ndp_query(&mut self).await?;
                    (
                        make_icmp6_echo_request(&self.target, sequence_number.0, dst_mac),
                        Target::Icmp6(Icmp6Target {
                            addr: expect_ipv6_addr(self.target.addr.clone()),
                            sequence_number: sequence_number.0
                        })
                    )
                },
            };
            sequence_number += Wrapping(1);
            self.stream.write(&request).await.unwrap();
            let sent = Instant::now();
            trace!("sent     {:?}", id);

            let resp_fut = self.get_response(&id, sent);
            match timeout(req_interval, resp_fut).await {
                Ok((duration, _response_data)) => {
                    let duration_nanos = duration.as_nanos() as u64;
                    {
                        let id = id.clone();
                        task::spawn_blocking(move || {
                            log_rtt(id, duration_nanos);
                        });
                    }
                    trace!("received {:?} rtt {:?}", &id, duration);
                    if let Some(remaining) = req_interval.checked_sub(duration) {
                        task::sleep(remaining).await;
                    }
                },
                Err(_) => {
                    warn!("timeout exceeded for {:?}", &id);
                },
            }
        }
    }

}

impl Probe {
    pub fn new(targets: Vec<TargetConfig>) -> Probe {
        Probe { targets }
    }

    fn targets_by_iface(self: Arc<Self>) -> HashMap<String, Vec<TargetConfig>> {
        let mut res = HashMap::new();

        for target in &self.targets {
            if !res.contains_key(&target.iface) {
                res.insert(target.iface.clone(), vec![target.clone()]);
            } else {
                let targets = res.get_mut(&target.iface).unwrap();
                targets.push(target.clone());
            }
        }

        res
    }

    async fn fill_incoming_stream(self: Arc<Self>, iface: String, tx: Sender<(Instant, Target, ResponseData)>, mut stream: RawPacketStream) -> Result<()> {
        let mut buf = [0u8; 1500];
        let mac = get_mac(&iface)?;

        loop {
            stream.read(&mut buf).await?;
            let mut buf = &buf[..];

            let ethernet = match EthernetPacket::new(&buf) {
                Some(p) => p,
                None => continue,
            };
            buf = &buf[EthernetPacket::minimum_packet_size()..];
            if ethernet.get_destination() != mac { continue };
            let msg = match ethernet.get_ethertype() {
                EtherTypes::Arp => {
                    let arp = match ArpPacket::new(&buf) {
                        Some(p) => p,
                        None => continue,
                    };
                    if arp.get_operation() != ArpOperations::Reply { continue };
                    let addr = arp.get_sender_proto_addr();
                    let l2addr = arp.get_sender_hw_addr();

                    (Instant::now(), Target::Arp(ArpTarget { addr }), ResponseData::Arp { l2addr })
                },
                EtherTypes::Ipv4 => {
                    let ipv4 = match Ipv4Packet::new(&buf) {
                        Some(p) => p,
                        None => continue,
                    };
                    buf = &buf[Ipv4Packet::minimum_packet_size()..];
                    // if ipv4.get_destination() != ??? { continue; }
                    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp { continue };
                    let addr = ipv4.get_source();

                    let icmp = match IcmpPacket::new(&buf) {
                        Some(p) => p,
                        None => continue,
                    };
                    if icmp.get_icmp_type() != IcmpTypes::EchoReply { continue };

                    let icmp_reply = match icmp::echo_reply::EchoReplyPacket::new(&buf) {
                        Some(p) => p,
                        None => continue,
                    };
                    let sequence_number = icmp_reply.get_sequence_number();

                    (Instant::now(), Target::Icmp(IcmpTarget { addr, sequence_number }), ResponseData::Icmp)
                },
                EtherTypes::Ipv6 => {
                    let ipv6 = match Ipv6Packet::new(&buf) {
                        Some(p) => p,
                        None => continue,
                    };
                    buf = &buf[Ipv6Packet::minimum_packet_size()..];
                    // if ipv6.get_destination() != ??? { continue; }
                    if ipv6.get_next_header() != IpNextHeaderProtocols::Icmpv6 { continue };
                    let addr = ipv6.get_source();

                    let icmp = match Icmpv6Packet::new(&buf) {
                        Some(p) => p,
                        None => continue,
                    };
                    match icmp.get_icmpv6_type() {
                        Icmpv6Types::NeighborAdvert => {
                            let n_advert = match NeighborAdvertPacket::new(&buf) {
                                Some(p) => p,
                                None => continue,
                            };
                            let options = n_advert.get_options();
                            let l2addr_option = match options.into_iter()
                                .find(|p| p.option_type == NdpOptionTypes::TargetLLAddr) {
                                Some(option) => option,
                                None => continue,
                            };
                            let l2addr_octets: [u8; 6] = match l2addr_option.data.try_into() {
                                Ok(octets) => octets,
                                Err(_) => continue,
                            };
                            let l2addr = l2addr_octets.into();
                            (Instant::now(), Target::Ndp(NdpTarget { addr }), ResponseData::Ndp { l2addr })
                        },
                        Icmpv6Types::EchoReply => {
                            let icmp_reply = match icmpv6::echo_reply::EchoReplyPacket::new(&buf) {
                                Some(p) => p,
                                None => continue,
                            };
                            let sequence_number = icmp_reply.get_sequence_number();

                            (Instant::now(), Target::Icmp6(Icmp6Target { addr, sequence_number }), ResponseData::Icmp6)
                        },
                        _ => continue,
                    }
                },
                _ => continue,
            };
            tx.send(msg).await.unwrap();
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut tasks = Vec::new();
        let probe = Arc::new(self);

        for (iface, targets) in probe.clone().targets_by_iface() {
            let (tx, rx) = bounded(16);
            let stream = get_stream(&iface)?;
            tasks.push(task::spawn(probe.clone().fill_incoming_stream(iface, tx, stream.clone())));

            let mut task_senders = vec![];
            for target in targets {
                let (tx, rx) = bounded(16);
                task_senders.push(tx);
                let task = TargetTask {
                    target,
                    incoming_stream: rx,
                    stream: stream.clone(),
                };
                tasks.push(task::spawn(task.run()));
            }

            tasks.push(task::spawn(async move {
                loop {
                    let msg = rx.recv().await.unwrap();
                    for tx in &task_senders {
                        if let Err(e) = tx.try_send(msg.clone()) {
                            warn!("channel send failed: {}", e);
                        }
                    }
                }
            }));
        }

        join_all(tasks).await.into_iter().collect::<Result<()>>()
    }
}
