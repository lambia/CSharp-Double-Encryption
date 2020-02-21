using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DoubleEncryption.Models
{
    public class CryptoRequestModel
    {
        public string Key { get; set; }
        public string Vector { get; set; }
        public string File { get; set; }
        public string Message { get; set; }
        public string FileByte { get; set; }
    }
}
