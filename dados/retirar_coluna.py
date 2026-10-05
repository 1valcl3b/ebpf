import pandas as pd


df = pd.read_csv('trafego_h264.csv')


df_novo = df.drop('Timestamp_kernel_ns', axis=1)


df_novo.to_csv('trafego.csv', index=False)
