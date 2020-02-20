using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

using RSAWebApp.Models;

namespace RSAWebApp.Services
{
    public static class MemoryCache
    {
        //Variabili di configurazione
        public static int _keyLength = 2048;

        //Istanza di RSA
        public static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(_keyLength);

        //Variabili d'appoggio
        public static RSAKeyPair keyPair = new RSAKeyPair()
        {
            publicKey = rsa.ToXmlString(false),
            privateKey = rsa.ToXmlString(true)
        };
        public static string publicKeyPem = CryptoService.PublicXML2PEM(rsa);
    }
}
