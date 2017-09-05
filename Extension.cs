using BusinessLayer.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BusinessLayer.Extensions
{
   public static class Extension
    {

       public static StringContent Response(this object Data, int Code, string Message, string SubMessage="")
        {
            ack Response = new ack();
            Response.Code = Code;
            Response.Message = Message;
            Response.SubMessage = SubMessage;

            var json = JsonConvert.SerializeObject(new { Data, Response });

        StringContent strcon = new StringContent(json.AndroidEncrypt(), Encoding.UTF8, "text/plain");
         //  StringContent strcon = new StringContent(json, Encoding.UTF8, "text/plain");

            return strcon;
        }




       #region Encrypt/Decrypt between Java and .NET methods


       public static dynamic ToAnyObject<T>(this string JsonString)
       {

           var json = JsonConvert.DeserializeObject<T>(JsonString);
           return json;
       }
       //public static UserLogin ToUserLogin(this string Data)
       //{

       // var json = JsonConvert.DeserializeObject<UserLogin>(Data);
       //  return json;
       //}

       //public static Lawsuit ToLawsuit(this string Data)
       //{
       //    var json = JsonConvert.DeserializeObject<Lawsuit>(Data);
       //    return json;
       //}

       //public static Account ToAccount(this string Data)
       //{
       //    var json = JsonConvert.DeserializeObject<Account>(Data);
       //    return json;
       //}

       //public static AppInfo ToAppInfo(this string Data)
       //{

       //    var json = JsonConvert.DeserializeObject<AppInfo>(Data);
       //    return json;
       //}
       #endregion


       public static int ToInt(this String TxtNumber)
        {
            int num = 0;
            int.TryParse(TxtNumber, out num);
            return num;
        }
        public static Int64 ToInt64(this String TxtNumber)
        {
            Int64 num = 0;
            Int64.TryParse(TxtNumber, out num);
            return num;
        }
        public static bool ToBool(this String TextString)
        {
            bool flag = false;
            bool.TryParse(TextString, out flag);
            return flag;
        }
        public static bool ToBool(this int TextNumber)
        {
            bool flag = false;
            if (TextNumber == 1) { flag = true; }
            else { flag = false; }
            return flag;
        }


       //AES
        private static string Key = "123";
        private static string IV = "zxcvbnmdfrasdfgh";
        public static string AESEncrypt(this string plainText)
        {
            byte[] plaintextbytes = System.Text.Encoding.ASCII.GetBytes(plainText);
            byte[] encrypted;

            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = 256;

            Rfc2898DeriveBytes pass = new Rfc2898DeriveBytes(Key, System.Text.ASCIIEncoding.ASCII.GetBytes("sarisari"), 1000);

            aes.Key = pass.GetBytes(32);
            aes.IV = pass.GetBytes(16);

            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;



            ICryptoTransform crypto = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, crypto, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {

                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }


            //   byte[] encrypted = crypto.TransformFinalBlock(plaintextbytes, 0, plaintextbytes.Length);
            // crypto.Dispose();
            return Convert.ToBase64String(encrypted);
        }
        public static string AESDecrypt(this string cipherText)
        {

            string plaintext;
            byte[] encryptedbytes = Convert.FromBase64String(cipherText);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            aes.KeySize = 256;


            Rfc2898DeriveBytes pass = new Rfc2898DeriveBytes(Key, System.Text.ASCIIEncoding.ASCII.GetBytes("sarisari"), 1000);

            aes.Key = pass.GetBytes(32);
            aes.IV = pass.GetBytes(16);
            //aes.Key = System.Text.ASCIIEncoding.ASCII.GetBytes(Key);
            //aes.IV = System.Text.ASCIIEncoding.ASCII.GetBytes(IV);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform crypto = aes.CreateDecryptor(aes.Key, aes.IV);



            using (MemoryStream msDecrypt = new MemoryStream(encryptedbytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, crypto, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }


            // byte[] secret = crypto.TransformFinalBlock(encryptedbytes, 0, encryptedbytes.Length);
            //  crypto.Dispose();
            //   return System.Text.ASCIIEncoding.ASCII.GetString(plaintext);
            return plaintext;

        }





       //Android
        #region Encrypt/Decrypt between Java and .NET methods

        private static string secretKey = "01TracksMenaIPIbraheem!CRMMobileAPI@23062015";
        public static RijndaelManaged GetRijndaelManaged()
        {
            var keyBytes = new byte[16];
            var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
            Array.Copy(secretKeyBytes, keyBytes, Math.Min(keyBytes.Length, secretKeyBytes.Length));
            return new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                KeySize = 128,
                BlockSize = 128,
                Key = keyBytes,
                IV = keyBytes
            };
        }

        private static byte[] Encrypt(byte[] plainBytes, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateEncryptor()
                .TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }
        private static byte[] Decrypt(byte[] encryptedData, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateDecryptor()
                .TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }
        public static string AndroidEncrypt(this string plainText)
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            return Convert.ToBase64String(Encrypt(plainBytes, GetRijndaelManaged()));
        }
        public static string AndroidDecrypt(this string cipherText)
        {
            var encryptedBytes = Convert.FromBase64String(cipherText);
            return Encoding.UTF8.GetString(Decrypt(encryptedBytes, GetRijndaelManaged()));
        }
        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }
        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        #endregion








    }

}
