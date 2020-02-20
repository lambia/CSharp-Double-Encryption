using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using System.IO;

using DoubleEncryption.Models;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DoubleEncryption.Services
{
    public class CryptoService
    {
        private static int _keyLength = 2048;
        private static int _blockSize = 256;
        private static int _chunkSize = 245;
        private static string _gs = "|";
        private static string _gsRegex = @"\|";
        private static string _path = "c:\\tmp\\";

        //public static int _keyLength = 2048;
        //public static readonly RSACryptoServiceProvider _rsa = new RSACryptoServiceProvider(_keyLength);
        //public static readonly RSAKeyPair _keyPair = new RSAKeyPair()
        //{
        //    publicKey = _rsa.ToXmlString(false),
        //    privateKey = _rsa.ToXmlString(true)
        //};
        //public static string _publicKeyPem = PublicXML2PEM(_rsa);

        public static string PublicXML2PEM(RSACryptoServiceProvider rsa)
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

        private byte[] padByteArray(byte[] byteArray, byte newByte, int newLength)
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

        public string rsaDecrypt(string encB64)
        {
            byte[] encBytes = Convert.FromBase64String(encB64);

            //Paddding aggiuntivo per javascript se i block size non fossero corretti
            if (encBytes.Length < _blockSize)
            {
                encBytes = padByteArray(encBytes, (byte)0x00, _blockSize);
            }

            // Create an array to store the decrypted data in it
            byte[] decBytes = MemoryCache.rsa.Decrypt(encBytes, false);

            // Get the string value from the decryptedData byte array
            UTF8Encoding byteConverter = new UTF8Encoding();
            string decB64 = byteConverter.GetString(decBytes);

            return decB64;
        }

        public byte[] aesEncrypt(string filename, string key, string vector)
        {
            //byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] vectorBytes = Convert.FromBase64String(vector);

            string fileB64 = readFile(filename);

            byte[] encrypted = aesEncryptString(fileB64, keyBytes, vectorBytes);
            //string result = Convert.ToBase64String(encrypted);
            //string result = Newtonsoft.Json.JsonConvert.SerializeObject(new { file = encrypted});

            return encrypted;
        }

        public string aesDecrypt(string encrypted, string key, string vector)
        {
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] vectorBytes = Convert.FromBase64String(vector);

            string result = aesDecryptBytes(encryptedBytes, keyBytes, vectorBytes);

            return result;
        }

        private static byte[] aesEncryptString(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        private static string aesDecryptBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        public void writeFile(string fileString, string fileName)
        {
            byte[] decryptedBinary = Convert.FromBase64String(fileString);
            File.WriteAllBytes(_path + fileName, decryptedBinary);
        }
        public string readFile(string fileName)
        {
            byte[] file = File.ReadAllBytes(_path + fileName);
            string fileB64 = Convert.ToBase64String(file);
            return fileB64;
        }

    }
}
