import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.metrics import  classification_report
from sklearn.metrics import ConfusionMatrixDisplay
import matplotlib.pyplot as plt

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

def prepare_dataset_v3(df, verbose=False):
    cleanup_dataset_ferrag(df)

    # to_drop_1_unique_loc = ['','']

def prepare_dataset_v1(df, verbose=False):
    """basic dataset leanup and onehot encoding"""
    cleanup_dataset_ferrag(df)

    mixed_zeros = ['mqtt.topic', 
                    'mqtt.conack.flags', 
                    'mqtt.protoname',
                    'dns.qry.name.len',
                    'http.request.method',
                    'http.referer', 
                    'http.request.version']

    for col in mixed_zeros:
        df.loc[(df[col] == '0') | (df[col] == '0x00000000'), col] = '0.0'

    drop_na_dups(df, verbose)
    df['Attack_type'] = df['Attack_type'].astype('category')

    object_col = [col for col in df.columns if df[col].dtype == 'object']
    for col in object_col:
        encode_text_dummy(df, col)

def prepare_dataset_v02(df, verbose=False):
    """With datetype fixes"""

    DROP = 'DROP'
    TARGET = 'TARGET'
    UNKNOWN = 'UNKNOWN'
    SINGLE_VAL = 'SINGLE_VAL'
    FIX_0 = 'FIX_0'
    TO_CAT = 'TO_CAT'
    TO_NUM = 'TO_NUM'
    TO_BOOL = 'TO_BOOL'

    feature_actions = {
            'frame.time' : [DROP],
            'ip.src_host' : [DROP],
            'ip.dst_host' : [DROP],
            'arp.dst.proto_ipv4' : [DROP],
            'arp.opcode' : [TO_NUM],
            'arp.hw.size' : [TO_NUM],
            'arp.src.proto_ipv4' : [DROP],
            'icmp.checksum' : [TO_NUM],
            'icmp.seq_le' : [TO_NUM],
            'icmp.transmit_timestamp' : [DROP],
            'icmp.unused' : [SINGLE_VAL],
            'http.file_data' : [DROP], #
            'http.content_length' : [TO_NUM],
            'http.request.uri.query' : [DROP],
            'http.request.method': [FIX_0, TO_CAT],
            'http.referer': [FIX_0, TO_CAT],
            'http.request.full_uri': [DROP],
            'http.request.version': [FIX_0, TO_CAT],
            'http.response': [TO_BOOL, TO_CAT],
            'http.tls_port': [SINGLE_VAL],
            'tcp.ack': [TO_NUM],
            'tcp.ack_raw': [TO_NUM],
            'tcp.checksum': [TO_NUM],
            'tcp.connection.fin': [TO_CAT],
            'tcp.connection.rst': [TO_CAT],
            'tcp.connection.syn': [TO_CAT],
            'tcp.connection.synack': [TO_CAT],
            'tcp.dstport': [DROP], #
            'tcp.flags': [TO_NUM],
            'tcp.flags.ack': [TO_BOOL, TO_CAT],
            'tcp.len': [TO_NUM],
            'tcp.options': [DROP], #
            'tcp.payload': [DROP], #
            'tcp.seq': [TO_NUM],
            'tcp.srcport': [DROP],
            'udp.port': [DROP],
            'udp.stream': [TO_NUM],
            'udp.time_delta': [UNKNOWN],
            'dns.qry.name': [UNKNOWN],
            'dns.qry.name.len': [FIX_0, TO_BOOL, TO_NUM], #[FIX_0, TO_CAT],
            'dns.qry.qu': [TO_BOOL, TO_CAT],
            'dns.qry.type': [SINGLE_VAL],
            'dns.retransmission': [TO_BOOL, TO_CAT],
            'dns.retransmit_request': [TO_CAT],
            'dns.retransmit_request_in': [SINGLE_VAL],
            'mqtt.conack.flags': [SINGLE_VAL],
            'mqtt.conflag.cleansess': [TO_BOOL, TO_CAT],
            'mqtt.conflags': [TO_NUM],
            'mqtt.hdrflags': [TO_NUM],
            'mqtt.len': [TO_NUM],
            'mqtt.msg_decoded_as': [SINGLE_VAL],
            'mqtt.msg': [DROP], #
            'mqtt.msgtype': [TO_NUM],
            'mqtt.proto_len': [TO_NUM],
            'mqtt.protoname': [FIX_0, TO_CAT],
            'mqtt.topic': [FIX_0, TO_CAT],
            'mqtt.topic_len': [TO_NUM],
            'mqtt.ver': [TO_NUM],
            'mbtcp.len': [SINGLE_VAL],
            'mbtcp.trans_id': [SINGLE_VAL],
            'mbtcp.unit_id': [SINGLE_VAL],
            'Attack_label': [TARGET],
            'Attack_type': [TARGET]
        }


    drop_columns = []
    encode_columns = []
    for feature, actions in feature_actions.items():
        if DROP in actions or SINGLE_VAL in actions:
            drop_columns.append(feature)
            continue

        if FIX_0 in actions:
            df.loc[(df[feature] == '0') | (df[feature] == '0x00000000'), feature] = '0.0'
        if TO_BOOL in actions:
            df[feature] = df[feature].apply(lambda x: '0.0' if str(x) in ['0.0', '0'] else '1.0')

        if TO_CAT in actions:
            encode_columns.append(feature)
            if df[feature].dtype != object:
                df[feature] = df[feature].astype('object')

        if TO_NUM in actions and df[feature].dtype != np.float64:
            df[feature] = df[feature].astype('float64')

        if TARGET in actions:
             df[feature] = df[feature].astype('category')

    df.drop(drop_columns, axis=1, inplace=True)

    drop_na_dups(df, verbose)

    for feature in encode_columns:
        encode_text_dummy(df, feature)

    

target_label_2_class = 'Attack_label' # 0 indicates normal and 1 indicates attacks
target_label_15_class = 'Attack_type'

def get_X_y(dataset, target):
    y = dataset[target]
    X = dataset.drop([target_label_2_class, target_label_15_class], axis=1, inplace=False)
    return X, y

def ds_split(dataset, test_size=0.2, seed=None):
    """Simple split, stratify against Attack_type"""
    return train_test_split(dataset, test_size=test_size, random_state=seed, stratify=dataset[target_label_15_class])

def make_2_class(dataset):
    return get_X_y(dataset, target_label_2_class)

def make_14_class(dataset):
    loc_df = dataset.drop(dataset[dataset[target_label_2_class] == 0].index, inplace=False)
    return get_X_y(loc_df, target_label_15_class)

def make_15_class(dataset):
    return get_X_y(dataset, target_label_15_class)

def ds_detection_split(dataset, seed=None):
    """"Normal vs Attack, 2 classes"""
    X, y = get_X_y(dataset, target_label_2_class)
    return train_test_split(X, y, test_size=0.2, random_state=seed, stratify=y)

def ds_classification_split(dataset, seed=None):
    """Split on Attack_type, 14 classes"""
    loc_df = dataset.drop(dataset[dataset[target_label_2_class] == 0].index, inplace=False)
    X, y = get_X_y(loc_df, target_label_15_class)
    return train_test_split(X, y, test_size=0.2, random_state=seed, stratify=y)

def dataset_split_15classes(dataset, seed=None):
    """Split on Attack_type, 15 classes"""
    X, y = get_X_y(dataset, target_label_15_class)
    return train_test_split(X, y, test_size=0.3, random_state=seed, stratify=y)

def report(y_train, y_train_predict, y_test, y_test_predict, le=None):

    if le:
        y_train = le.inverse_transform(y_train)
        y_train_predict = le.inverse_transform(y_train_predict)
        y_test = le.inverse_transform(y_test)
        y_test_predict = le.inverse_transform(y_test_predict)

    print('TRAIN:')
    print(classification_report(y_train, y_train_predict))

    print('TEST:')
    print(classification_report(y_test, y_test_predict))

def plot_cm(y_true, y_predict, le=None):

    if le:
        y_true = le.inverse_transform(y_true)
        y_predict = le.inverse_transform(y_predict)

    title='Normalized confusion matrix'

    disp = ConfusionMatrixDisplay.from_predictions(
        y_true,
        y_predict,
        # display_labels=Attack_type_classes,
        cmap=plt.cm.Blues,
        normalize='true',
        values_format='.2f'
    )
    disp.ax_.set_title(title)
    disp.figure_.set_size_inches(8, 8, forward=True)
    plt.xticks(rotation=90)
    plt.show()

def show_cr(y_test, y_test_predict):

    cr = classification_report(y_test, y_test_predict, output_dict=True)

    paper_cols = ['Normal',
                'Back',
                'HTTP',
                'ICMP',
                'TCP',
                'UDP',
                'Fing',
                'MITM',
                'Pwd',
                'Port',
                'Rans',
                'SQL',
                'Upload',
                'Scan',
                'XSS']

    map_to_paper = {'Normal':'Normal',
                    'Back':'Backdoor',
                    'HTTP':'DDoS_HTTP',
                    'ICMP':'DDoS_ICMP',
                    'TCP':'DDoS_TCP',
                    'UDP':'DDoS_UDP',
                    'Fing':'Fingerprinting',
                    'MITM':'MITM',
                    'Pwd':'Password',
                    'Port':'Port_Scanning',
                    'Rans':'Ransomware',
                    'SQL':'SQL_injection',
                    'Upload':'Uploading',
                    'Scan':'Vulnerability_scanner',
                    'XSS':'XSS'
                    }

    header='{:^10}|'*16
    cols_pattern='{:^10}|' + '{:^10.2f}|'*15

    metrics = ['precision', 'recall', 'f1-score']

    print(header.format('Metr', *paper_cols))
    print(header.format(*['-'*10]*16))

    # print(cr)
    for m in metrics:
        vals = []
        for col in paper_cols:
            vals.append(cr[map_to_paper[col]][m])

        print(cols_pattern.format(m, *vals), f'{cr["accuracy"]:0.2f}')

    print(header.format(*['-'*10]*16))






    















# def prepare_dataset(path_to_dataset, verbose=False):
#     df  = pd.read_csv(path_to_dataset, low_memory=False)

#     cleanup_dataset_ferrag(df)

#     df.drop(to_drop_1_unique, axis=1, inplace=True)
    
#     drop_na_dups(df, verbose)

#     for col in mixed_zeros:
#         df.loc[(df[col] == '0.0') | (df[col] == '0x00000000'), col] = '0.0'
#         encode_text_dummy(df, col)

#     df['Attack_type'] = df['Attack_type'].astype('category')

#     if verbose:
#         print('#'*80)
#         print('TARGET: "Attack_label"')
#         print(df['Attack_label'].value_counts())
#         print('-'*80)
#         print('TARGET: "Attack_type"')
#         print(df['Attack_type'].value_counts())
#         print('#'*80)

#     return df
