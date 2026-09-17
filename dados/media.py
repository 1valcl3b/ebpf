import pandas as pd

df = pd.read_csv('rodadas.csv')

coluna1 = 'Pacotes I'

coluna2 = 'Pacotes Non-I'

media1 = df[coluna1].mean()

media2 = df[coluna2].mean()

print(f'A média de {coluna1} é: {media1}')

print(f'A média de {coluna2} é: {media2}') 
