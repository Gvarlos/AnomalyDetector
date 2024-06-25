import socket
import csv
import tensorflow as tf
from scapy.all import *
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import sys

def Get_statistics():                           
    server = socket.socket()                     
    port = 29541
    server.bind((IP_get, port))                    
    server.listen(5)                              

    con, _ = server.accept()                        
    filename = "received_statistics.csv"            
    file = open(filename, "wb")                     

    while True:
        data = con.recv(1024)                       
        file.write(data)                            
        if not data: break                         

    file.close()                                    
    neural_network_analysis()                      

def neural_network_analysis():
    model = tf.keras.models.load_model('Model_neiro.keras')
    data = pd.read_csv("received_statistics.csv", header=None, encoding='ISO-8859-1', on_bad_lines='skip', skiprows=1)

    X = data                                       
    data = data.values.tolist()                    

    cat_cols = [0, 1, 2, 3, 4, 5, 18, 19]          
    for col in cat_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])

                                                    
    num_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    scaler = StandardScaler()
    X[num_cols] = scaler.fit_transform(X[num_cols])

    predictions = model.predict(X)
    predicted_classes = np.argmax(predictions, axis=-1)
    class_labels = ["Нормальный трафик", "Аномальный трафик"]  

    with open('Anomaly_packet.csv', 'a', newline='') as file:
        writer = csv.writer(file, delimiter = "\t")

        for i, pred in enumerate(predicted_classes):
            if class_labels[pred] == "Аномальный трафик" and predictions[i][pred] > 0.4:
                formatted_data = [str(elem) + ',' for elem in data[i]]
                result = ''.join(formatted_data)
                print(f"Предсказание: {class_labels[pred]} - Вероятность: {predictions[i][pred]}")
                print(f"Аномальный пакет - {result}")
                writer.writerow(f"Предсказание: {class_labels[pred]} - Вероятность: {predictions[i][pred]}")
                writer.writerow(f"Аномальный пакет - {result}")

sys.setrecursionlimit(10000)
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.connect(('10.255.255.255', 1))
IP_get = server.getsockname()[0]
port = 29541                                   
print(f"IP адрес сервера - {IP_get}, порт - {port}")
while True:
    Get_statistics()


