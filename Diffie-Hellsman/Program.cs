using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Diffie_Hellsman
{
    public static class Cipher
    {
        public static string Encrypt(string plainText, string password)
        {
            if (plainText == null)
            {
                return null;
            }

            if (password == null)
            {
                password = String.Empty;
            }

            var bytesToBeEncrypted = Encoding.UTF8.GetBytes(plainText);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            var bytesEncrypted = Cipher.Encrypt(bytesToBeEncrypted, passwordBytes);

            return Convert.ToBase64String(bytesEncrypted);
        }

        public static string Decrypt(string encryptedText, string password)
        {
            if (encryptedText == null)
            {
                return null;
            }

            if (password == null)
            {
                password = String.Empty;
            }

            var bytesToBeDecrypted = Convert.FromBase64String(encryptedText);
            var passwordBytes = Encoding.UTF8.GetBytes(password);

            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            var bytesDecrypted = Cipher.Decrypt(bytesToBeDecrypted, passwordBytes);

            return Encoding.UTF8.GetString(bytesDecrypted);
        }

        private static byte[] Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);

                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }

                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }

        private static byte[] Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            var saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);

                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }

                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;
        }
    }
    class Key_Functions
    {
        //COMPUTE PUBLIC VALUES
        public static BigInteger GetPublicNumber(BigInteger prime, BigInteger root, int priv_key)
        {
            return  BigInteger.Pow(root , priv_key) % prime;
        }

        //COMPUTE SYM SECRET KEY
        public static BigInteger GetSymKey(BigInteger prime, BigInteger pub_key, int priv_key)
        {
            return BigInteger.Pow(pub_key , priv_key) % prime;
        }
    }
    class Program
    {
        
        static void Main(string[] args)
        {
            BigInteger A_Sym_B;
            BigInteger A_Public;

            BigInteger B_Sym_A;
            BigInteger B_Public;

            Console.WriteLine("/////////////////////// DIFFIE-HELLMAN ////////////////////////");

            Console.Write("Selecione o numero primo: ");
            BigInteger prime = new BigInteger(Int32.Parse(Console.ReadLine()));

            Console.Write("Selecione a primative root do numero primo anterior: ");
            BigInteger root = new BigInteger(Int32.Parse(Console.ReadLine()));

            Console.Write("Selecione a chave privada de A: ");
            int A_Private =  Int32.Parse(Console.ReadLine());

            Console.Write("Selecione a chave privada de B: ");
            int B_Private = Int32.Parse(Console.ReadLine());
            
            //Calcula os numeros publicos
            A_Public = Key_Functions.GetPublicNumber(prime, root, A_Private);
            B_Public = Key_Functions.GetPublicNumber(prime, root, B_Private);

            //Calculam chaves simetricas secretas
            A_Sym_B = Key_Functions.GetSymKey(prime, B_Public, A_Private);
            B_Sym_A = Key_Functions.GetSymKey(prime, A_Public, B_Private);

            Console.WriteLine("----------------------A---------------------- ");
            Console.WriteLine("Chave Privada: " + A_Private + "; Chave Publica: "+ A_Public + ";");
            Console.WriteLine("Chave Simetrica A -> B: " + A_Sym_B);
            Console.WriteLine("----------------------B----------------------- ");
            Console.WriteLine("Chave Privada: " + B_Private + "; Chave Publica: " + B_Public + ";");
            Console.WriteLine("Chave Simetrica B -> A: " + B_Sym_A);

            Console.WriteLine("----------------------Enviar Mensagem A -> B ---------------------- ");
            Console.Write("Mensagem: ");
            string msg = Console.ReadLine();

            Console.Write("Segredo: ");
            string segredo = Console.ReadLine();
            Console.WriteLine("------------Mensagem-> " + Cipher.Encrypt(msg, A_Sym_B.ToString()));

            Console.WriteLine("-----------Mensagem Decifrada em B->" + Cipher.Decrypt(Cipher.Encrypt(msg, A_Sym_B.ToString()), B_Sym_A.ToString()));

        }
    }
}
