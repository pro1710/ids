import pandas as pd

def drop_na_dups(df, verbose=False):
    if verbose:
        print(f'Before: dropna: NA: {df.isnull().sum().sum()}, DUPS: {df.duplicated().sum()}', )

    df.dropna(axis=0, how='any', inplace=True)
    df.drop_duplicates(subset=None, keep='first', inplace=True)

    if verbose:
        print(f'After: dropna: NA: {df.isnull().sum().sum()}, DUPS: {df.duplicated().sum()}', )

def encode_text_dummy(df, name):
    dummies = pd.get_dummies(df[name])
    
    for x in dummies.columns:
        dummy_name = f"{name}-{x}"
        df[dummy_name] = dummies[x]
    df.drop(name, axis=1, inplace=True)


dropped_by_ferrag = ['frame.time', 
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

def cleanup_dataset_ferrag(df):
    df.drop(dropped_by_ferrag, axis=1, inplace=True)

def ferrag_preparation(df, verbose=False):
    if verbose:
        print(f'Before: shape={df.shape}')
    cleanup_dataset_ferrag(df)
    drop_na_dups(df, verbose)
    if verbose:
        print(f'After: shape={df.shape}')

to_drop_1_unique = ['icmp.unused',
                    'http.tls_port',
                    'dns.qry.type',
                    'dns.retransmit_request_in',
                    'mqtt.conack.flags',
                    'mqtt.msg_decoded_as',
                    'mbtcp.len',
                    'mbtcp.trans_id',
                    'mbtcp.unit_id']

mixed_zeros = ['mqtt.topic', 
            #   'mqtt.conack.flags', 
                'mqtt.protoname',
                'dns.qry.name.len',
                'http.request.method',
                'http.referer', 
                'http.request.version']





def prepare_dataset(path_to_dataset, verbose=False):
    df  = pd.read_csv(path_to_dataset, low_memory=False)

    cleanup_dataset_ferrag(df)

    df.drop(to_drop_1_unique, axis=1, inplace=True)
    
    drop_na_dups(df, verbose)

    for col in mixed_zeros:
        df.loc[(df[col] == '0.0') | (df[col] == '0x00000000'), col] = '0.0'
        encode_text_dummy(df, col)

    df['Attack_type'] = df['Attack_type'].astype('category')

    if verbose:
        print('#'*80)
        print('TARGET: "Attack_label"')
        print(df['Attack_label'].value_counts())
        print('-'*80)
        print('TARGET: "Attack_type"')
        print(df['Attack_type'].value_counts())
        print('#'*80)

    return df
