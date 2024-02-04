import pandas as pd


def encode_text_dummy(df, name):
    dummies = pd.get_dummies(df[name])
    
    for x in dummies.columns:
        dummy_name = f"{name}-{x}"
        df[dummy_name] = dummies[x]
    df.drop(name, axis=1, inplace=True)


def prepare_dataset(path_to_dataset):
    df  = pd.read_csv(path_to_dataset, low_memory=False)

    to_drop_columns = ['frame.time', 
                'ip.src_host', 
                'ip.dst_host', 
                'arp.src.proto_ipv4',
                'arp.dst.proto_ipv4', 
                'http.file_data',
                'http.request.full_uri',
                'icmp.transmit_timestamp',
                'http.request.uri.query', 
                'tcp.options',
                'tcp.payload',
                'tcp.srcport',
                'tcp.dstport', 
                'udp.port', 
                'mqtt.msg']

    df.drop(to_drop_columns, axis=1, inplace=True)
    print(f'drop: NA: {df.isnull().sum().sum()}, DUPS: {df.duplicated().sum()}', )

    to_drop_1_unique = ['icmp.unused',
                    'http.tls_port',
                    'dns.qry.type',
                    'dns.retransmit_request_in',
                    'mqtt.msg_decoded_as',
                    'mbtcp.len',
                    'mbtcp.trans_id',
                    'mbtcp.unit_id',
                    'mqtt.conack.flags']

    df.drop(to_drop_1_unique, axis=1, inplace=True)
    print(f'drop: NA: {df.isnull().sum().sum()}, DUPS: {df.duplicated().sum()}', )

    df.dropna(axis=0, how='any', inplace=True)
    print(f'dropna: NA: {df.isnull().sum().sum()}, DUPS: {df.duplicated().sum()}', )

    to_fix_columns = ['mqtt.topic', 
                    #   'mqtt.conack.flags', 
                      'mqtt.protoname',
                      'dns.qry.name.len',
                      'http.request.method',
                      'http.referer', 
                      'http.request.version']
    
    for col in to_fix_columns:
        df.loc[(df[col] == '0.0') | (df[col] == '0x00000000'), col] = '0'
        encode_text_dummy(df, col)


    df.drop_duplicates(subset=None, keep='first', inplace=True)
    print(f'drop_duplicates: NA: {df.isnull().sum().sum()}, DUPS: {df.duplicated().sum()}', )

    df['Attack_type'] = df['Attack_type'].astype('category')

    print('#'*80)
    print('TARGET: "Attack_label"')
    print(df['Attack_label'].value_counts())
    print('-'*80)
    print('TARGET: "Attack_type"')
    print(df['Attack_type'].value_counts())
    print('#'*80)

    return df