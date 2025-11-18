//! # Connection
//! This module contains the general API for the conntrack library.

use neli::{
    Size, ToBytes,
    consts::{genl::NlAttrType, nl::*, socket::*},
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, Nlattr, NlattrBuilder},
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::{NlRouter, NlRouterReceiverHandle},
    types::{Buffer, GenlBuffer},
    utils::Groups,
};
use std::net::IpAddr;

use crate::attributes::*;
use crate::decoders::*;
use crate::message::*;
use crate::model::*;
use crate::result::*;

/// The `Conntrack` type is used to connect to a netfilter socket and execute
/// conntrack table specific commands.
pub struct Conntrack {
    socket: NlRouter,
}

impl Conntrack {
    /// This method opens a netfilter socket using a `socket()` syscall, and
    /// returns the `Conntrack` instance on success.
    pub fn connect() -> Result<Self> {
        let socket = NlRouter::connect(NlFamily::Netfilter, Some(0), Groups::empty())?.0;
        Ok(Self { socket })
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub fn dump(&self) -> Result<Vec<Flow>> {
        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(0u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(GenlBuffer::<ConntrackAttr, Buffer>::new())
            .build()?;

        let recv_iter = self.socket.send(
            CtNetlinkMessage::Conntrack,
            NlmF::DUMP,
            NlPayload::Payload(genlhdr),
        )?;

        let mut flows = Vec::new();
        for result in recv_iter {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = result?;
            if let NlPayload::Payload(message) = result.nl_payload() {
                let handle = message.attrs().get_attr_handle();

                flows.push(Flow::decode(handle)?);
            }
        }

        Ok(flows)
    }

    pub fn delete(&self, proto: u8, ip: &IpAddr, src: bool) -> Result<()> {
        let (top_attr_type, attr_type, bin) = match ip {
            IpAddr::V4(ipv4) => {
                let bin = ipv4.octets().to_vec();
                if src {
                    (ConntrackAttr::CtaTupleOrig, IpTupleAttr::CtaIpv4Src, bin)
                } else {
                    (ConntrackAttr::CtaTupleReply, IpTupleAttr::CtaIpv4Dst, bin)
                }
            }
            IpAddr::V6(ipv6) => {
                let bin = ipv6.octets().to_vec();
                if src {
                    (ConntrackAttr::CtaTupleOrig, IpTupleAttr::CtaIpv6Src, bin)
                } else {
                    (ConntrackAttr::CtaTupleReply, IpTupleAttr::CtaIpv6Dst, bin)
                }
            }
        };

        let ip_attr = make_attr(attr_type, false, Buffer::from(bin))?;
        let ip_tuple = make_attr(TupleAttr::CtaTupleIp, true, ip_attr)?;
        let proto_attr = make_attr(
            ProtoTupleAttr::CtaProtoNum,
            false,
            Buffer::from((proto as u32).to_ne_bytes().to_vec()),
        )?;
        let proto_tuple = make_attr(TupleAttr::CtaTupleProto, true, proto_attr)?;

        let mut attr = make_attr(top_attr_type, true, ip_tuple)?;
        attr = attr.nest(&proto_tuple)?;
        let mut attrs = GenlBuffer::<ConntrackAttr, Buffer>::new();
        attrs.push(attr);

        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(libc::AF_INET as u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(attrs)
            .build()?;

        let x: NlRouterReceiverHandle<u16, Buffer> = self.socket.send(
            CtNetlinkMessage::CtDelete,
            NlmF::ACK | NlmF::MATCH,
            NlPayload::Payload(genlhdr),
        )?;

        log::info!("waiting...");
        for r in x {
            log::info!("{r:?}");
        }
        log::info!("done");

        Ok(())
    }
}

fn make_attr<T, P>(attr_type: T, nest: bool, payload: P) -> Result<Nlattr<T, Buffer>>
where
    P: Size + ToBytes,
    T: NlAttrType,
{
    Ok(NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(attr_type)
                .nla_nested(nest)
                .build()?,
        )
        .nla_payload(payload)
        .build()?)
}
