import glob
import os

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from skl2onnx import convert_sklearn, update_registered_converter
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx.common.shape_calculator import calculate_linear_classifier_output_shapes
from onnxmltools.convert.lightgbm.operator_converters.LightGbm import convert_lightgbm

# skl2onnx no soporta LightGBM de forma nativa: registramos el conversor de onnxmltools
# lgb.LGBMClassifier: Es la clase de LightGBM que usamos para clasificar los datos
# 'LightGbmLGBMClassifier': Es el nombre que le damos al conversor
# calculate_linear_classifier_output_shapes: Es la función que calcula la forma de la salida
# convert_lightgbm: Es la función que convierte el modelo
# options: Es un diccionario que especifica las opciones de conversión
update_registered_converter(
    lgb.LGBMClassifier,
    'LightGbmLGBMClassifier',
    calculate_linear_classifier_output_shapes,
    convert_lightgbm,
    options={'nocl': [True, False], 'zipmap': [True, False, 'columns']},
)

# Se definen las variables que se usarán para entrenar el modelo
# Flow Duration: Duración del flujo en milisegundos
# Total Fwd Packets: Número total de paquetes enviados por el cliente
# Total Backward Packets: Número total de paquetes enviados por el servidor
# Flow Bytes/s: Bytes totales divididos por la duración del flujo
# Flow Packets/s: Paquetes totales divididos por la duración del flujo
# Packet Length Variance: Varianza en la longitud de los paquetes
# Flow IAT Std: Desviación estándar de los intervalos entre paquetes
# SYN Flag Count: Número de paquetes con el flag SYN
# ACK Flag Count: Número de paquetes con el flag ACK
# Nota: Debemos establecer si requeriremos que el modelo aprenda a reconocer otros ataques maliciosos o no
# si sí, entonces puede ser que las 9 columnas no sean suficientes o debemos encontrar otros datasets
SELECTED_FEATURES = [
    ' Flow Duration',
    ' Total Fwd Packets',
    ' Total Backward Packets',
    'Flow Bytes/s',
    ' Flow Packets/s',
    ' Packet Length Variance',
    ' Flow IAT Std',
    ' SYN Flag Count',
    ' ACK Flag Count'
    ]

# Se define la columna que se usará como etiqueta para entrenar el modelo
TARGET_COLUMN = ' Label'

# Función para cargar y limpiar el dataset de entrada
# csv_path: Ruta del archivo CSV o carpeta con archivos CSV

def load_and_clean_dataset(csv_path):
    # Acepta un solo CSV o una carpeta con varios CSV
    if os.path.isdir(csv_path):
        files = sorted(glob.glob(os.path.join(csv_path, "*.csv"))) #.glob busca todos los archivos que coincidan con el patrón
        if not files:
            raise FileNotFoundError(f"No hay CSV en {csv_path}")
    else:
        files = [csv_path]

    frames = []
    for f in files:
        print(f"Cargando el dataset: {os.path.basename(f)}")
        # latin-1: el CSV de WebAttacks trae bytes que no son UTF-8 válido, el UTF-8 es el estandar de codificación de caracteres para internet
        frames.append(pd.read_csv(f, usecols=SELECTED_FEATURES + [TARGET_COLUMN],
                                  encoding="latin-1", low_memory=False))
    df = pd.concat(frames, ignore_index=True)
    del frames #liberamos memoria

    print("Limpiando los valores infinitos y Nan")
    # np.inf es el valor infinito, np.nan es el valor no disponible (Not a Number)
    # inplace=True significa que modificamos el DataFrame original
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # dropna() elimina las filas que contienen valores NaN
    df.dropna(inplace=True)

    labels = df[TARGET_COLUMN].str.strip()
    print("\nFilas por etiqueta:\n" + labels.value_counts().to_string())

    X = df[SELECTED_FEATURES].astype(np.float32)
    y = (labels != 'BENIGN').astype(np.int8)

    return X, y, labels

# La siguiente función entrena el modelo y lo exporta a ONNX
def train_and_export(X, y, labels):
    print("Dividimos los datos de entrenamiento y lo los de test")
    # Estratificamos por etiqueta original para que cada tipo de ataque (PortScan, DoS, ...) aparezca en el test
    X_train, X_test, y_train, y_test, lbl_train, lbl_test = train_test_split(
        X, y, labels, test_size = 0.2, random_state = 42, stratify = labels)

    print("Entrenando el modelo LightGBM para Edge")
    #Hiperparametros restringidos para mantener el binario ONNX muy pequeño ya que debemos poder cargarlo en memoriaRAM en el dispositivo con pocos recursos
    #n_estimators: número de árboles
    #max_depth: profundidad máxima de los árboles
    #learning_rate: tasa de aprendizaje
    #random_state: semilla para la generación de números aleatorios
    #n_jobs: número de núcleos a utilizar
    clf = lgb.LGBMClassifier(
        n_estimators= 50,
        max_depth = 7,
        learning_rate = 0.1,
        random_state = 42,
        n_jobs = -1
    )

    clf.fit(X_train, y_train)

    print("\n Evaluación del modelo :")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Benigno', 'Ataque']))
    print("Matriz de Confusión:\n", confusion_matrix(y_test, y_pred)) # la matriz de confusión muestra los falsos positivos y falsos negativos

    print("\n Detección por tipo de tráfico (test):")
    print(f"  {'Etiqueta':<35}{'Filas':>10}{'Acierto':>10}")
    results = pd.DataFrame({'label': lbl_test.to_numpy(), 'pred': y_pred})
    for lbl, grp in results.groupby('label'):
        expected = 0 if lbl == 'BENIGN' else 1
        print(f"  {lbl:<35}{len(grp):>10,}{(grp['pred'] == expected).mean():>10.4f}")

    print("\n Exportando el modelo a onnx rutime")
    #Definimos el tensor de entrada 1 fila 9 columnas; un tensor es el que utilizan las redes neuronales para
    #procesar datos
    initial_type = [('float_input', FloatTensorType([None, len(SELECTED_FEATURES)]))]
    onnx_model = convert_sklearn(
        clf,
        initial_types = initial_type,
        target_opset = {'': 12, 'ai.onnx.ml': 2},
        options = {id(clf): {'zipmap': False}}  # salida de probabilidades como tensor simple
    )

    with open("firewall_edge_model.onnx", "wb") as f:
        f.write(onnx_model.SerializeToString())
    print("Modelo guardado como firewall_edge_model.onnx")

if __name__ == "__main__":
    # Carpeta completa de CIC-IDS2017 (también acepta la ruta de un solo CSV)
    CSV_PATH = "/home/valenturas_cardenas/Documentos/Firewall_CM/Firewall_CM/MachineLearningCVE"

    try:
        X, y, labels = load_and_clean_dataset(CSV_PATH)
        train_and_export(X, y, labels)  
    except FileNotFoundError:
        print("Error: No se encontro el archivo.")
    except Exception as e:
        print("Error inesperado:", e)    
    
    

    
    