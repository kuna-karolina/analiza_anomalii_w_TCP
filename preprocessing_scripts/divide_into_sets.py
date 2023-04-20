import pandas as pd

# Wczytanie pliku CSV
df = pd.read_csv('SQL_injection_attack_preprocessed.csv')

# Podzielenie na zbiór uczący i testowy w proporcji 80/20
train_df = df.sample(frac=0.8, random_state=1)
test_df = df.drop(train_df.index)
#
# Zapisanie zbiorów do osobnych plików CSV
train_df.to_csv('train.csv', index=False)
test_df.to_csv('test.csv', index=False)
