import pandas as pd
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

#
## Metoda drzew decyzyjnych - RandomForest -> wykorzystuję tą metodę
#

src_host_vectorizer = TfidfVectorizer()
dst_host_vectorizer = TfidfVectorizer()

def getX(host_features, dst_features, add_features, fit=False):
    if fit:
        src_host_vectorized = src_host_vectorizer.transform(host_features)
        dst_host_vectorized = dst_host_vectorizer.transform(dst_features)
    else:
        src_host_vectorized = src_host_vectorizer.fit_transform(host_features)
        dst_host_vectorized = dst_host_vectorizer.fit_transform(dst_features)

    return hstack([src_host_vectorized, dst_host_vectorized, add_features])


def learn():
    data = pd.read_csv('res_result/train_data.csv', low_memory=False)

    src_host_features = data['ip.src_host'].values.astype('U')
    dst_host_features = data['ip.dst_host'].values.astype('U')
    additional_features = data[['icmp.seq_le', 'tcp.ack']].values

    X = getX(src_host_features, dst_host_features, additional_features)
    y = data['Attack_label']

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    rf_model = RandomForestClassifier()
    rf_model.fit(X_train, y_train)

    y_val_pred = rf_model.predict(X_val)
    accuracy = accuracy_score(y_val, y_val_pred)

    # test_data = pd.read_csv('res_original/ML_EdgeIIoT_dataset.csv', low_memory=False)
    test_data = pd.read_csv('res_result/test_data.csv', low_memory=False)

    src_host_features_test = test_data['ip.src_host'].values.astype('U')
    dst_host_features_test = test_data['ip.dst_host'].values.astype('U')
    additional_features_test = test_data[['icmp.seq_le', 'tcp.ack']].values

    X_test = getX(src_host_features_test, dst_host_features_test, additional_features_test, fit=True)

    y_test = test_data['Attack_label']
    y_test_pred = rf_model.predict(X_test)
    accuracy_test = accuracy_score(y_test, y_test_pred)


    attack_count = 0
    normal_count = 0
    not_recognized_attack = 0
    for i in range(len(test_data)):
        label = test_data.loc[i, 'Attack_label']
        prediction = y_test_pred[i]
        if prediction == 1 and prediction == label:
            attack_count += 1
        elif prediction == 0:
            if label != prediction:
                not_recognized_attack += 1
            else:
                normal_count += 1

    num_of_all_attack = (test_data['Attack_label'] == 1).sum()
    num_of_normal_request = (test_data['Attack_label'] == 0).sum()

    print("----------------------------------------------------------------------------")
    print("------------------  DANE DLA WYKRYWANIA ANOMALII - DDoS  -------------------")
    print("----------------------------------------------------------------------------")
    print("{:<50} {:>10} rekordów".format("Ilość testowych danych:", test_data.index.stop))
    print("{:<50} {:>10}".format("Testowe dane ataku:", num_of_all_attack))
    print("{:<50} {:>10}".format("Testowe dane neutralne:", num_of_normal_request))
    print("{:<50} {:>10}".format("Dokładność modelu (zbioru walidacyjnego):", round(accuracy,2 )))
    print("{:<50} {:>10}".format("Dokładność modelu (zbioru testowego):", round(accuracy_test, 2)))
    print("____________________________________________________________________________")
    print("-------------------  WYNIKI KOŃCOWE WYKRYWANIA ANOMALII  -------------------")
    print("{:<50} {:>10}/{:>0} ~ {:>0}%".format("Liczba ataków (wykrytych):", attack_count, num_of_all_attack,
                                                round((attack_count / num_of_all_attack) * 100, 2)))
    print("{:<50} {:>10}".format("Liczba danych neutralnych (wykrytych):", normal_count))
    print("{:<50} {:>10}".format("Liczba danych ataków (niewykrytych):", not_recognized_attack))
    print("{:<50} {:>10} rekordów".format("Łącznie:", not_recognized_attack + normal_count + attack_count))
    print("____________________________________________________________________________")


if __name__ == "__main__":
    learn()
