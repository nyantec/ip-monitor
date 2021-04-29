use std::time::{Duration, SystemTime, Instant};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use super::{Error, Result, none};
use super::config::{TargetConfig, TargetType};
use afpacket::r#async::RawPacketStream;
use log::{debug, info};
use async_std::task;
use async_std::sync::Mutex;
use async_std::io::prelude::{WriteExt, ReadExt};
use pnet::packet::arp::{MutableArpPacket, ArpPacket, ArpHardwareTypes, ArpOperations, Arp};
use pnet::packet::ethernet::{MutableEthernetPacket, EthernetPacket, EtherTypes, Ethernet};
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet, Ipv4};
use pnet::packet::ipv4;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::{MutableEchoRequestPacket, EchoRequest, IcmpCodes};
use pnet::util::MacAddr;
use pnet::packet::Packet;
use pnet::util::checksum;
use futures::future::join_all;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TargetIdentifier (TargetType, Ipv4Addr);

fn get_mac(iface: &str) -> Result<MacAddr> {
    let interface = pnet::datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface)
        .ok_or_else(|| none!("network interface"))?;

    Ok(interface.mac.ok_or_else(|| none!("interface mac"))?)
}

fn get_stream(iface: &str) -> Result<RawPacketStream> {
    let mut stream = RawPacketStream::new()?;
    stream.bind(&iface)?;
    Ok(stream)
}

fn make_arp_request(target: &TargetConfig) -> Result<Vec<u8>> {
    let source_mac = get_mac(&target.iface)?;

    let arp = Arp {
        hardware_type: ArpHardwareTypes::Ethernet,
        protocol_type: EtherTypes::Ipv4,
        hw_addr_len: 6,
        proto_addr_len: 4,
        operation: ArpOperations::Request,
        sender_hw_addr: source_mac,
        sender_proto_addr: target.source_addr,
        target_hw_addr: MacAddr::zero(),
        target_proto_addr: target.addr.clone(),
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

    Ok(ethernet_packet.packet().to_vec())
}

fn make_icmp_echo_request(target: &TargetConfig) -> Result<Vec<u8>> {
    let source_mac = get_mac(&target.iface)?;

    let icmp = EchoRequest {
        icmp_type: IcmpTypes::EchoRequest,
        icmp_code: IcmpCodes::NoCode,
        checksum: 0,
        identifier: 0,
        sequence_number: ((SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() % (u16::MAX as u64)) as u16),
        payload: vec![],
    };

    let mut icmp_buffer = [0u8; 40];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
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
        source: target.source_addr,
        destination: target.addr,
        options: vec![],
        payload: icmp_packet.packet().to_vec(),
    };

    let mut ipv4_buffer = [0u8; 61];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.populate(&ipv4);
    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable())); // needed?

    let ethernet = Ethernet {
        destination: MacAddr::broadcast(),
        source: source_mac,
        ethertype: EtherTypes::Ipv4,
        payload: ipv4_packet.packet().to_vec(),
    };

    let mut ethernet_buffer = [0u8; 75];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.populate(&ethernet);

    Ok(ethernet_packet.packet().to_vec())
}

#[derive(Debug)]
pub struct Probe {
    targets: Vec<TargetConfig>,
    last_sent: Mutex<HashMap<TargetIdentifier, Instant>>,
}

impl Probe {
    pub fn new(targets: Vec<TargetConfig>) -> Probe {
        Probe {
            targets,
            last_sent: Mutex::new(HashMap::new()),
        }
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

    async fn recv_group(self: Arc<Self>, iface: String, targets: Vec<TargetConfig>) -> Result<()> {
        let mut buf = [0u8; 1500];
        let mut stream = get_stream(&iface)?;
        let mac = get_mac(&iface)?;

        loop {
            stream.read(&mut buf).await?;
            let ethernet = EthernetPacket::new(&buf).unwrap();
            if ethernet.get_destination() != mac { continue };
            let id = match ethernet.get_ethertype() {
                EtherTypes::Arp => {
                    let arp = ArpPacket::new(&buf[EthernetPacket::minimum_packet_size()..]).unwrap();
                    if arp.get_operation() != ArpOperations::Reply { continue };
                    let addr = arp.get_sender_proto_addr();

                    TargetIdentifier (TargetType::Arp, addr)
                },
                EtherTypes::Ipv4 => {
                    let ipv4 = Ipv4Packet::new(&buf[EthernetPacket::minimum_packet_size()..]).unwrap();
                    // if ipv4.get_destination() != ??? { continue; }
                    if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp { continue };
                    let addr = ipv4.get_source();

                    let icmp = IcmpPacket::new(&buf[EthernetPacket::minimum_packet_size()+Ipv4Packet::minimum_packet_size()..]).unwrap();
                    if icmp.get_icmp_type() != IcmpTypes::EchoReply { continue };

                    TargetIdentifier (TargetType::Icmp, addr)
                },
                _ => continue,
            };
            let now = Instant::now();

            if let Some(last_sent) = self.last_sent.lock().await.get(&id) {
                let duration = now.duration_since(*last_sent);
                info!("received {:?} rtt {:?}", id, duration);
            } else {
                debug!("unsolicited {:?}", id);
                continue
            }
        }
    }

    async fn send_target(self: Arc<Self>, target: TargetConfig) -> Result<()> {
        let mut stream = get_stream(&target.iface)?;

        let id = TargetIdentifier (target.r#type.clone(), target.addr.clone());
        let request = match target.r#type {
            TargetType::Arp => make_arp_request(&target)?,
            TargetType::Icmp => make_icmp_echo_request(&target)?,
        };

        loop {
            task::sleep(Duration::from_millis(1000)).await;
            self.last_sent.lock().await.insert(id.clone(), Instant::now());
            info!("sent {:?}", id);
            stream.write(&request).await.unwrap();
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut tasks = Vec::new();
        let probe = Arc::new(self);

        for (iface, targets) in probe.clone().targets_by_iface() {
            tasks.push(task::spawn(probe.clone().recv_group(iface, targets)));
        }

        for target in &probe.clone().targets {
            tasks.push(task::spawn(probe.clone().send_target(target.clone())));
        }

        join_all(tasks).await.into_iter().collect::<Result<()>>()
    }
}
