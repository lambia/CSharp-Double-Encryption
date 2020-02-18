using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using DoubleEncryption.Models;

namespace DoubleEncryption.Services
{
    public class RSAService
    {
        public RSAKeyPair handshake()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            //RSAKeyPair chiaviXML = new RSAKeyPair()
            //{
            //    publicKey = rsa.ToXmlString(false),
            //    privateKey = rsa.ToXmlString(true)
            //};
            //RSAKeyPair chiaviPEM = new RSAKeyPair()
            //{
            //    publicKey = PublicXML2PEM(rsa),
            //    privateKey = PrivateXML2PEM(rsa)
            //};

            RSAKeyPair chiavi = new RSAKeyPair()
            {
                publicKey = PublicXML2PEM(rsa),
                privateKey = rsa.ToXmlString(true)
            };
            return chiavi;
        }


        public static IEnumerable<string> Split(string str, int chunkSize)
        {
            if (string.IsNullOrEmpty(str) || chunkSize < 1)
                throw new ArgumentException("String can not be null or empty and chunk size should be greater than zero.");
            var chunkCount = str.Length / chunkSize + (str.Length % chunkSize != 0 ? 1 : 0);
            for (var i = 0; i < chunkCount; i++)
            {
                var startIndex = i * chunkSize;
                if (startIndex + chunkSize >= str.Length)
                    yield return str.Substring(startIndex);
                else
                    yield return str.Substring(startIndex, chunkSize);
            }
        }

        public string encrypt(string publicKey, string text, bool pem)
        {
            // Convert the text to an array of bytes
            UTF8Encoding byteConverter = new UTF8Encoding();
            byte[] dataToEncrypt = byteConverter.GetBytes(text);

            // Create a byte array to store the encrypted data in it
            byte[] encryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                //per gestire javascript che usa formato pem
                if (pem == true)
                {
                    publicKey = PublicPemToXml(publicKey);
                }
                // Set the rsa pulic key
                rsa.FromXmlString(publicKey);

                // Encrypt the data and store it in the encyptedData Array
                // MAX 245 bytes
                encryptedData = rsa.Encrypt(dataToEncrypt, false);
            }
            // Base 64 encode enctrypted data
            return Convert.ToBase64String(encryptedData);
        }

        public string EncryptLongText(string publicKey, string text, bool pem)
        {
            var strOutput = "";
            var stringParts = Split(text, 245);
            foreach (var stringPart in stringParts)
            {
                strOutput += encrypt(publicKey, stringPart, pem) + "|";
            }
            return strOutput;
        }

        public byte[] padByteArray(byte[] byteArray, byte newByte, int newLength)
        {
            byte[] result = new byte[newLength];
            int oldLength = byteArray.Length;
            int newBytesNumber = newLength - oldLength;

            byteArray.CopyTo(result, newBytesNumber);

            for (int i = 0; i < newBytesNumber; i++)
            {
                result[i] = (byte)newByte;
            }

            return result;
        }


        public string decrypt(string privateKey, string text, bool pem)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(text);

            if(dataToDecrypt.Length<256)
            {
                dataToDecrypt = padByteArray(dataToDecrypt, (byte)0x00, 256);
            }
            
            // Create an array to store the decrypted data in it
            byte[] decryptedData;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                //per gestire javascript che usa formato pem
                if (pem == true)
                {
                    privateKey = PrivatePemToXml(privateKey);
                }
                // Set the private key of the algorithm
                rsa.FromXmlString(privateKey);
                decryptedData = rsa.Decrypt(dataToDecrypt, false);
            }


            // Get the string value from the decryptedData byte array
            UTF8Encoding byteConverter = new UTF8Encoding();
            string decryptedBase64 = byteConverter.GetString(decryptedData);

            return decryptedBase64;
        }

        public string DecryptLongText(string privateKey, string text, bool pem)
        {
            var strOutput = "";
            var stringParts = Regex.Split(text, @"\|xGSy\|");
            bool inError = false;
            
            for (int i = 0; i < stringParts.Length; i++)
            {
                string stringPart = stringParts[i];
                if (stringPart != "")
                {
                    string buffer = decrypt(privateKey, stringPart, pem);
                    if(buffer==null)
                    {
                        strOutput = "Errore chunk: " + i.ToString() + " - Contenuto: " + stringPart;
                        inError = true;
                        break;
                    } else
                    {
                        strOutput += buffer;
                    }
                }
            }

            //Vecchio ciclo senza debug
            //foreach (var stringPart in stringParts)
            //{
            //    if (stringPart != "") strOutput += decrypt(privateKey, stringPart, pem);
            //}

            if(!inError)
            {
                byte[] decryptedBinary = Convert.FromBase64String(strOutput);
                File.WriteAllBytes("c:\\tmp\\prova.png", decryptedBinary);
            }

            return strOutput;
        }

        private static string PrivateXML2PEM(RSACryptoServiceProvider rsa)
        {
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);

            if (keyPair != null) // if XML RSA key contains private key
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
                return FormatPem(privateKeyInfo.GetEncoded(), "RSA PRIVATE KEY");
            }

            return null;
        }
        private static string PublicXML2PEM(RSACryptoServiceProvider rsa)
        {
            RsaKeyParameters publicKey = DotNetUtilities.GetRsaPublicKey(rsa);

            if (publicKey != null) // if XML RSA key contains public key
            {
                SubjectPublicKeyInfo publicKeyInfo =
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                return FormatPem(publicKeyInfo.GetEncoded(), "PUBLIC KEY");
            }

            return null;
        }

        private static string FormatPem(byte[] pemBytes, string keyType)
        {
            string pem = Convert.ToBase64String(pemBytes);
            var sb = new StringBuilder();
            sb.AppendFormat("-----BEGIN {0}-----\n", keyType);

            int line = 1, width = 64;

            while ((line - 1) * width < pem.Length)
            {
                int startIndex = (line - 1) * width;
                int len = line * width > pem.Length
                              ? pem.Length - startIndex
                              : width;
                sb.AppendFormat("{0}\n", pem.Substring(startIndex, len));
                line++;
            }

            sb.AppendFormat("-----END {0}-----\n", keyType);
            return sb.ToString();
        }


        //private static string Base64Encode(string plainText)
        //{
        //    var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        //    return System.Convert.ToBase64String(plainTextBytes);
        //}

        //private string Base64Decode(string base64EncodedData)
        //{
        //    var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
        //    return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        //}

        public static string PublicPemToXml(string pem)
        {
            string xml = null;
            xml = GetXmlRsaKey(pem, obj =>
            {
                var publicKey = (RsaKeyParameters)obj;
                return DotNetUtilities.ToRSA(publicKey);
            }, rsa => rsa.ToXmlString(false));

            return xml;
        }
        public static string PrivatePemToXml(string pem)
        {
            string xml = null;
            xml = GetXmlRsaKey(pem, obj =>
                {
                    if ((obj as RsaPrivateCrtKeyParameters) != null)
                        return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)obj);
                    var keyPair = (AsymmetricCipherKeyPair)obj;
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
                }, rsa => rsa.ToXmlString(true));
            return xml;
        }

        private static string GetXmlRsaKey(string pem, Func<object, RSA> getRsa, Func<RSA, string> getKey)
        {
            using (var ms = new MemoryStream())
            using (var sw = new StreamWriter(ms))
            using (var sr = new StreamReader(ms))
            {
                sw.Write(pem);
                sw.Flush();
                ms.Position = 0;
                var pr = new PemReader(sr);
                object keyPair = pr.ReadObject();
                using (RSA rsa = getRsa(keyPair))
                {
                    var xml = getKey(rsa);
                    return xml;
                }
            }
        }
    }
}
