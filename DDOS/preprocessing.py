import pandas as pd

origin_file_name = "ML_EdgeIIoT_dataset.csv"
deleted_column_file_name = "deleted_column.csv"
clear_data_file = 'clear_data.csv'
train_data_file = 'train_data.csv'
test_data_file = 'test_data.csv'


def delete_column():
    df = pd.read_csv("res_original/{0}".format(origin_file_name), low_memory=False)

    df = df[~(df['Attack_type'] != "Normal") | ~(df['Attack_type'] != "DDoS_ICMP")]

    df = df.drop(columns=["Attack_type", "mqtt.protoname", "mbtcp.trans_id", "mqtt.topic", "mqtt.topic_len", "mqtt.ver",
                          "mbtcp.len", "mbtcp.unit_id", "http.file_data", "http.content_length",
                          "http.request.uri.query", "http.request.method", "http.referer", "http.request.full_uri",
                          "http.request.version", "http.response", "http.tls_port", "udp.port", "udp.stream",
                          "udp.time_delta", "dns.qry.name", "dns.qry.name.len", "dns.qry.qu", "dns.qry.type",
                          "dns.retransmission", "dns.retransmit_request", "dns.retransmit_request_in",
                          "mqtt.conack.flags", "mqtt.conflag.cleansess", "mqtt.conflags", "mqtt.hdrflags",
                          "mqtt.len", "mqtt.msg_decoded_as", "mqtt.msg", "mqtt.msgtype", "mqtt.proto_len",
                          "arp.dst.proto_ipv4", "arp.opcode", "arp.hw.size", "arp.src.proto_ipv4"])

    df.to_csv("res_result/{0}".format(deleted_column_file_name), index=False)


def clear_data():
    df = pd.read_csv("res_result/{0}".format(deleted_column_file_name), low_memory=False)

    df.dropna(inplace=True)

    column_name = 'ip.src_host'
    value_to_delete = '0'
    df = df[df[column_name] != value_to_delete]

    df.to_csv('res_result/{0}'.format(clear_data_file), index=False)


def split_data():
    df = pd.read_csv("res_result/{0}".format(clear_data_file), low_memory=False)

    train_df = df.sample(frac=0.8, random_state=1)
    test_df = df.drop(train_df.index).sample(frac=1)

    train_df.to_csv('res_result/{0}'.format(train_data_file), index=False)
    test_df.to_csv('res_result/{0}'.format(test_data_file), index=False)


if __name__ == "__main__":
    delete_column()
    clear_data()
    split_data()
