using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

using DoubleEncryption.Models;
using DoubleEncryption.Services;

namespace DoubleEncryption.Controllers
{
    public class CryptoController : Controller
    {
        public IActionResult Index()
        {
            RSAKeyPair publicKey = new RSAKeyPair() { publicKey = MemoryCache.publicKeyPem };

            return View(publicKey);
        }

        [HttpGet]
        public string GetPublicKey() //ToDev: aggiungere parametro tipo ClientID o eliminare il metodo?
        {
            return MemoryCache.publicKeyPem;
        }

        [HttpPost]
        public string Download([FromBody] CryptoRequestModel payload)
        {
            //Filename: file richiesto, Key: aes-key, Message: aes-IV
            //string testKEY = "gCjK+DZ/GCYbKIGiAt1qCA==" oppure "hbcMV6bdumNyMm5wVRY7hsgpVy/EyErwr8hOi8MK0KM="
            //string testIV = "47l5QsSe1POo31adQ/u7nQ==" oppure "rN3II1WG73hpfwwdxtoDsw=="
            //key -> byte[32] { 133, 183, 12, 87, 166, 221, 186, 99, 114, 50, 110, 112, 85, 22, 59, 134, 200, 41, 87, 47, 196, 200, 74, 240, 175, 200, 78, 139, 195, 10, 208, 163 }
            //iv -> byte[16] { 172, 221, 200, 35, 85, 134, 239, 120, 105, 127, 12, 29, 198, 218, 3, 179 }

            CryptoService srv = new CryptoService();
            /*
            string keyAES = srv.rsaDecrypt(payload.key);
            string vectorAES = srv.rsaDecrypt(payload.vector);
            string file = srv.aesEncrypt(payload.file, keyAES, vectorAES);
            *///ToDev: decommenta
            
            byte[] fileBytes = srv.aesEncrypt(payload.File, payload.Key, payload.Vector); //ToDev: rimuovi
            string fileString = Convert.ToBase64String(fileBytes);
            //string response = Newtonsoft.Json.JsonConvert.SerializeObject(new { file = file });

            //return Encoding.UTF7.GetString(file);
            return fileString;
        }

        [HttpPost]
        public string Upload([FromBody] CryptoRequestModel payload)
        {
            CryptoService srv = new CryptoService();
            string keyAES = srv.rsaDecrypt(payload.Key);
            string vectorAES = srv.rsaDecrypt(payload.Vector);
            string fileString = srv.aesDecrypt(payload.File, keyAES, vectorAES);
            srv.writeFile(fileString, payload.Message);

            return "ok";
        }
    }
}