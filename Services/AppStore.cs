using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Configuration;

using DoubleEncryption.Models;

namespace DoubleEncryption.Services
{
    public static class AppStore
    {
        //Variabili di configurazione
        public static int _keyLength = 2048;
        public static int _blockSize = 256;
        public static string _gsRegex = @"\|";
        public static string _path = "storage\\"; //era "C:\\tmp\\"

        //Istanza di RSA
        public static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(_keyLength);

        //Variabili d'appoggio
        public static KeyPair keyPair = new KeyPair()
        {
            publicKey = rsa.ToXmlString(false),
            privateKey = rsa.ToXmlString(true)
        };
        public static string publicKeyPem = RSAService.PublicXML2PEM(rsa);
    }
}
