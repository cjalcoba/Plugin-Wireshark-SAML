# Plugin-Wireshark-SAML

Plugin para Wireshark para captura de tráfico SAML.

Requiere una construcción desde código fuente de Wireshark para cambiar la longitud de los paquetes capturados. 
En el archivo proto.h hay que poner item_label_length a un valor muy grande para capturar paquetes completos de SAML. Por ejemplo, item_label_length 20000.

