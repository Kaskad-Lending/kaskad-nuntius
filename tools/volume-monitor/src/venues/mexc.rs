//! MEXC trade stream — same endpoint + envelope as the collector
//! (`wss://wbs-api.mexc.com/ws`, `{"method":"SUBSCRIPTION","params":[...]}`,
//! `{"method":"PING"}` keepalive). Channel
//! `spot@public.aggre.deals.v3.api.pb@100ms@{SYMBOL}` (the non-aggre
//! variant is server-blocked). Data frames are binary protobuf
//! `PushDataV3ApiWrapper` with the deals body at field 314 (wire-verified;
//! depth uses 313). Items are individual executions batched per 100ms
//! window: price/quantity strings (quantity in BASE), time in ms, plus a
//! field-5 trade-id-range string not in the schema (skipped by prost).
//! No replay on subscribe. Live-verified 2026-07-19; frames re-captured
//! 2026-07-27 (see tests).

use crate::types::{EventTx, VenueCfg};
use crate::util::{ws_connect, IDLE_TIMEOUT};
use eyre::{eyre, Result};
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde_json::json;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/mexc.rs"));
}

const PING_INTERVAL: Duration = Duration::from_secs(30);

pub async fn run(cfg: &VenueCfg, tx: &EventTx) -> Result<()> {
    let mut ws = ws_connect(&cfg.ws_url).await?;
    let params: Vec<String> = cfg
        .pairs
        .iter()
        .map(|p| {
            format!(
                "spot@public.aggre.deals.v3.api.pb@100ms@{}",
                p.to_uppercase()
            )
        })
        .collect();
    ws.send(Message::Text(
        json!({"method": "SUBSCRIPTION", "params": params}).to_string(),
    ))
    .await?;
    cfg.send_connected(tx);
    let (mut write, mut read) = ws.split();
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if write
                    .send(Message::Text(json!({"method": "PING"}).to_string()))
                    .await
                    .is_err()
                {
                    return Err(eyre!("ping send failed"));
                }
            }
            msg = tokio::time::timeout(IDLE_TIMEOUT, read.next()) => match msg
                .map_err(|_| eyre!("idle: no frames for {IDLE_TIMEOUT:?}"))?
            {
                // Text frames are acks/PONGs; reject-acks say "Not Subscribed".
                Some(Ok(Message::Text(text))) => {
                    if text.contains("Not Subscribed") {
                        return Err(eyre!("mexc subscription rejected: {text}"));
                    }
                }
                Some(Ok(Message::Binary(bin))) => {
                    let Ok(wrapper) = proto::PushDataV3ApiWrapper::decode(&bin[..]) else {
                        continue;
                    };
                    for (sym, price, qty, ts) in parse_trades(&wrapper) {
                        let Some(pair) = cfg.pairs.iter().find(|p| p.eq_ignore_ascii_case(&sym))
                        else {
                            continue;
                        };
                        cfg.send_trade(tx, pair, price, qty, ts);
                    }
                }
                Some(Ok(Message::Ping(p))) => {
                    let _ = write.send(Message::Pong(p)).await;
                }
                Some(Ok(Message::Close(_))) | None => return Err(eyre!("WS closed")),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(eyre!("WS error: {e}")),
            }
        }
    }
}

/// Extracts (symbol, price, qty_base, ts_ms) rows from a decoded wrapper.
/// Frames without a `publicAggreDeals` body (other channel variants) yield
/// nothing. The symbol falls back to the channel's last `@` segment when
/// field 3 is absent. `time` is already unix ms.
fn parse_trades(wrapper: &proto::PushDataV3ApiWrapper) -> Vec<(String, f64, f64, i64)> {
    let Some(deals) = &wrapper.public_aggre_deals else {
        return Vec::new();
    };
    let sym = wrapper.symbol.clone().unwrap_or_else(|| {
        wrapper
            .channel
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_string()
    });
    deals
        .deals
        .iter()
        .filter_map(|d| {
            let (Ok(price), Ok(qty)) = (d.price.parse::<f64>(), d.quantity.parse::<f64>()) else {
                return None;
            };
            Some((sym.clone(), price, qty, d.time))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// BTCUSDT deals push captured 2026-07-27 (recv 1785141192390),
    /// re-encoded byte-exact from the recorded field walk: channel (f1),
    /// symbol (f3), sendTime (f6, value not retained by the capture —
    /// receive time substituted), deals body (f314) with two executions.
    /// Each item carries the field-5 trade-id-range string from the wire,
    /// which the schema omits.
    const DEALS_FRAME_HEX: &str = concat!(
        "0a2f73706f74407075626c69632e61676772652e6465616c732e76332e617069",
        "2e7062403130306d7340425443555344541a074254435553445430c6cdd395fa",
        "33d21398010a4a0a0836353231392e3338120a302e3134313931333032180220",
        "a2cdd395fa332a2937313033343239343836353032303932383058305f373130",
        "33343239343836353032303932383158300a4a0a0836353231392e3338120a30",
        "2e3134333430363634180120a5cdd395fa332a29373130333432393438363632",
        "37393231393258305f3731303334323934383636323739323139335830",
    );

    #[test]
    fn deals_push_decodes_and_parses() {
        let bin = unhex(DEALS_FRAME_HEX);
        let w = proto::PushDataV3ApiWrapper::decode(&bin[..]).expect("decode");
        assert_eq!(w.channel, "spot@public.aggre.deals.v3.api.pb@100ms@BTCUSDT");
        assert_eq!(w.symbol.as_deref(), Some("BTCUSDT"));
        let deals = w.public_aggre_deals.as_ref().expect("deals body");
        assert_eq!(deals.deals.len(), 2);
        assert_eq!(deals.deals[0].price, "65219.38");
        assert_eq!(deals.deals[0].quantity, "0.14191302");
        assert_eq!(deals.deals[0].trade_type, 2);
        assert_eq!(deals.deals[0].time, 1785141192354);
        assert_eq!(deals.deals[1].price, "65219.38");
        assert_eq!(deals.deals[1].quantity, "0.14340664");
        assert_eq!(deals.deals[1].trade_type, 1);
        assert_eq!(deals.deals[1].time, 1785141192357);

        let rows = parse_trades(&w);
        assert_eq!(
            rows,
            vec![
                ("BTCUSDT".to_string(), 65219.38, 0.14191302, 1785141192354),
                ("BTCUSDT".to_string(), 65219.38, 0.14340664, 1785141192357),
            ]
        );
        // time is epoch ms as-is (2026-07-27T08:33:12Z), no unit conversion.
        assert!(rows[0].3 > 1_700_000_000_000 && rows[0].3 < 2_000_000_000_000);
    }

    #[test]
    fn subscribe_ack_yields_no_trades() {
        // Verbatim ack captured 2026-07-27. It arrives as a Text frame,
        // which the read loop never protobuf-decodes; even fed to the
        // decoder it produces no trades.
        let ack = r#"{"id":0,"code":0,"msg":"spot@public.aggre.deals.v3.api.pb@100ms@BTCUSDT"}"#;
        let no_trades = match proto::PushDataV3ApiWrapper::decode(ack.as_bytes()) {
            Ok(w) => parse_trades(&w).is_empty(),
            Err(_) => true,
        };
        assert!(no_trades);
    }

    #[test]
    fn non_deals_wrapper_yields_nothing() {
        let w = proto::PushDataV3ApiWrapper {
            channel: "spot@public.aggre.depth.v3.api.pb@10ms@BTCUSDT".into(),
            symbol: Some("BTCUSDT".into()),
            symbol_id: None,
            create_time: None,
            send_time: Some(1785141192390),
            public_aggre_deals: None,
        };
        assert!(parse_trades(&w).is_empty());
    }

    #[test]
    fn symbol_falls_back_to_channel_tail() {
        let w = proto::PushDataV3ApiWrapper {
            channel: "spot@public.aggre.deals.v3.api.pb@100ms@TAOUSDT".into(),
            symbol: None,
            symbol_id: None,
            create_time: None,
            send_time: None,
            public_aggre_deals: Some(proto::PublicAggreDealsV3Api {
                deals: vec![proto::PublicAggreDealsV3ApiItem {
                    price: "437.62".into(),
                    quantity: "1.5".into(),
                    trade_type: 1,
                    time: 1785141192000,
                }],
                event_type: String::new(),
            }),
        };
        assert_eq!(
            parse_trades(&w),
            vec![("TAOUSDT".to_string(), 437.62, 1.5, 1785141192000)]
        );
    }

    #[test]
    fn unparsable_price_row_skipped() {
        let w = proto::PushDataV3ApiWrapper {
            channel: "spot@public.aggre.deals.v3.api.pb@100ms@BTCUSDT".into(),
            symbol: Some("BTCUSDT".into()),
            symbol_id: None,
            create_time: None,
            send_time: None,
            public_aggre_deals: Some(proto::PublicAggreDealsV3Api {
                deals: vec![
                    proto::PublicAggreDealsV3ApiItem {
                        price: "not-a-number".into(),
                        quantity: "1.0".into(),
                        trade_type: 1,
                        time: 1785141192354,
                    },
                    proto::PublicAggreDealsV3ApiItem {
                        price: "65219.38".into(),
                        quantity: "0.5".into(),
                        trade_type: 2,
                        time: 1785141192355,
                    },
                ],
                event_type: String::new(),
            }),
        };
        assert_eq!(
            parse_trades(&w),
            vec![("BTCUSDT".to_string(), 65219.38, 0.5, 1785141192355)]
        );
    }
}
