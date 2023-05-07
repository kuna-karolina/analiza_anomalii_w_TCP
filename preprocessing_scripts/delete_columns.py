import pandas as pd

df = pd.read_csv("SQL_injection_attack.csv")

# for ddos icmp maybe should stay

df = df.drop(columns=["Attack_type","http.file_data","http.content_length","http.request.uri.query","http.request.method","http.referer","http.request.full_uri",
                      "http.request.version","http.response","http.tls_port","udp.port","udp.stream","udp.time_delta","dns.qry.name","dns.qry.name.len","dns.qry.qu","dns.qry.type",
                      "dns.retransmission","dns.retransmit_request","dns.retransmit_request_in","mqtt.conack.flags","mqtt.conflag.cleansess","mqtt.conflags","mqtt.hdrflags",
                      "mqtt.len","mqtt.msg_decoded_as","mqtt.msg","mqtt.msgtype","mqtt.proto_len","arp.dst.proto_ipv4","arp.opcode","arp.hw.size","arp.src.proto_ipv4","icmp.checksum","icmp.seq_le","icmp.unused","icmp.transmit_timestamp"
                      ])
df.to_csv("SQL_injection_attack_with_deleted_columns.csv", index=False)