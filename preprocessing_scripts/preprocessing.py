import csv

import pandas as pd
from sklearn.preprocessing import MinMaxScaler

# Load the data into a pandas dataframe
df = pd.read_csv('SQL_injection_attack_with_deleted_columns.csv')

# Remove any rows with missing data
df.dropna(inplace=True)

# Set the column name and value to delete
column_name = 'ip.src_host'
value_to_delete = '0'

# Filter out rows with the value to delete in the specified column
df = df[df[column_name] != value_to_delete]

df.to_csv('SQL_injection_attack_filtered_values.csv', index=False, quoting=csv.QUOTE_NONNUMERIC)

scaler = MinMaxScaler()

# fit and transform the numeric variables
numeric_cols = ['tcp.ack', 'tcp.ack_raw', 'tcp.len', 'tcp.seq']

scaler.fit(df[numeric_cols])

df[numeric_cols] = scaler.transform(df[numeric_cols])

# Remove outliers using IQR method
for col in numeric_cols:
    q1 = df[col].quantile(0.25)
    q3 = df[col].quantile(0.75)
    iqr = q3 - q1
    low = q1 - 1.5 * iqr
    high = q3 + 1.5 * iqr
    df = df[(df[col] >= low) & (df[col] <= high)]

df.to_csv('scaled_data.csv', index=False)
