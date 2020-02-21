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
            CryptoService srv = new CryptoService();

            string key = srv.rsaDecrypt(payload.Key);
            string vector = srv.rsaDecrypt(payload.Vector);
            byte[] fileBytes = srv.aesEncrypt(payload.File, key, vector);

            string fileString = Convert.ToBase64String(fileBytes);
            return fileString;
        }

        [HttpPost]
        [DisableRequestSizeLimit]
        public string Upload([FromBody] CryptoRequestModel payload)
        {
            //ToDev: limite 10mb IIS in upload
            CryptoService srv = new CryptoService();
            
            string key = srv.rsaDecrypt(payload.Key);
            string vector = srv.rsaDecrypt(payload.Vector);
            string fileString = srv.aesDecrypt(payload.File, key, vector);

            srv.writeFile(fileString, payload.Message);
            return "ok";
            //ToDev: decommenta rsa e return http code
        }
    }
}