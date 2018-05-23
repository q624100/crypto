using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace crypto
{
    class Program
    {
        const int BUFFER_SIZE = 0x10000;
        const int MAX_SIZE = 100 * 1024 * 1024; // 100M

        static PgpPublicKey PublicKey;
        static PgpSecretKey SecretKey;
        static PgpPrivateKey PrivateKey;

        static SymmetricKeyAlgorithmTag KeyAlgorithm { get; set; }

        static void displayHelp()
        {
            Console.WriteLine("-e path_to_public_key null@null path_to_input_file path_to_output_file");
            Console.WriteLine("-d path_to_public_key path_to_private_key@password path_to_input_file path_to_output_file");
        }

        static void Main(string[] args)
        {
            // -e|-d 
            // path_to_public_key
            // path_to_private_key@password|null@null
            // path_to_input_file
            // path_to_output_file
            // 
            if (args.Length != 5)
            {
                displayHelp();
                return;
            }
            bool isEncrypt = args[0] == "-e";
            string pathPublic = args[1];
            string pathPrivate = args[2].Split('@')[0];
            string password = args[2].Split('@')[1];
            string pathInput = args[3];
            string pathOutput = args[4];

            PublicKey = GetPublicKey(pathPublic);
            SecretKey = (pathPrivate == "null") ? null : GetSecretKey(pathPrivate);
            if (SecretKey != null && !string.IsNullOrEmpty(password))
            {
                PrivateKey = SecretKey.ExtractPrivateKey(password.ToCharArray());
            }
            KeyAlgorithm = SymmetricKeyAlgorithmTag.TripleDes;

            if (isEncrypt)
            {
                Encrypt(pathInput, pathOutput);
            }
            else
            {
                Decrypt(pathInput, pathOutput);
            }
        }

        #region Get keys
        static PgpPublicKey GetPublicKey(string path)
        {
            Stream keyIn;
            if (File.Exists(path))
            {
                keyIn = File.OpenRead(path);
            }
            else
            {
                keyIn = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(_defaultPublicKey));
            }
            try
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
                {
                    var publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                    foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
                    {
                        PgpPublicKey key = kRing.GetPublicKeys()
                            .Cast<PgpPublicKey>()
                            .Where(k => k.IsEncryptionKey)
                            .FirstOrDefault();
                        if (key != null)
                        {
                            return key;
                        }
                    }
                }
            }
            finally
            {
                keyIn.Close();
                keyIn.Dispose();
            }
            return null;
        }

        static PgpSecretKey GetSecretKey(string path)
        {
            using (Stream keyIn = File.OpenRead(path))
            {
                using (Stream inputStream = PgpUtilities.GetDecoderStream(keyIn))
                {
                    var secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                    foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
                    {
                        PgpSecretKey key = kRing.GetSecretKeys()
                            .Cast<PgpSecretKey>()
                            .Where(k => k.IsSigningKey)
                            .FirstOrDefault();
                        if (key != null)
                        {
                            return key;
                        }
                    }
                }
            }
            return null;
        }
        #endregion

        #region File
        static void DeleteFileIfExists(string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        static void Encrypt(string inputFile, string outputFile)
        {
            DeleteFileIfExists(outputFile);
            var info = new FileInfo(inputFile);
            if (info.Length <= MAX_SIZE)
            {
                byte[] oriBytes = File.ReadAllBytes(inputFile);
                using (Stream outputStream = File.Create(outputFile))
                {
                    Encrypt(oriBytes, oriBytes.Length, "crypto", outputStream);
                }
                return;
            }
            var mapFile = outputFile + ".map";
            var buffer = new byte[MAX_SIZE];
            int i = 0;
            DeleteFileIfExists(mapFile);
            var logger = File.AppendText(mapFile);
            using (var inStream = File.OpenRead(inputFile))
            {
                while (true)
                {
                    int c = inStream.Read(buffer, 0, MAX_SIZE);
                    if (c == 0)
                    {
                        break;
                    }
                    i++;

                    using (Stream outputStream = File.Open(outputFile, FileMode.Append, FileAccess.Write))
                    {
                        var start = outputStream.Position;
                        Encrypt(buffer, c, "crypto", outputStream);
                        var end = outputStream.Position;

                        string log = string.Format("{0}:{1}:{2}", i.ToString("D9"), c, end - start);
                        logger.WriteLine(log);
                        Console.WriteLine(log);
                    }
                    GC.Collect();
                }
            }
            logger.Close();
            logger.Dispose();
        }

        static void Decrypt(string inputFile, string outputFile)
        {
            DeleteFileIfExists(outputFile);
            var mapFile = inputFile + ".map";
            bool isSmall = !File.Exists(mapFile);
            if (isSmall)
            {
                using (Stream inputStream = File.OpenRead(inputFile))
                {
                    using (Stream fOut = File.Create(outputFile))
                    {
                        Decrypt(inputStream, fOut);
                    }
                }
                return;
            }
            var maps = new List<string>(File.ReadAllLines(mapFile));
            using (Stream inputStream = File.OpenRead(inputFile))
            {
                var buffer = new byte[MAX_SIZE + 100 * 1024];
                foreach (var m in maps)
                {
                    Console.WriteLine(m);
                    // m -> part_no:origin_size:encrypted_size
                    var pars = m.Split(':');
                    var encSize = int.Parse(pars[2]);
                    var checkNo = inputStream.Read(buffer, 0, encSize);
                    if (checkNo != encSize)
                    {
                        Console.WriteLine("Wrong map: " + checkNo.ToString());
                        break;
                    }
                    using (var encStream = new MemoryStream(buffer, 0, encSize))
                    {
                        using (var aFile = new FileStream(outputFile, FileMode.Append, FileAccess.Write))
                        {
                            Decrypt(encStream, aFile);
                        }
                    }
                }
            }

        }
        #endregion

        static void Encrypt(byte[] data, int len, string name, Stream encStream)
        {
            byte[] bytes;
            using (var tempStream = new MemoryStream())
            {
                Stream inputStream = tempStream;
                var lData = new PgpLiteralDataGenerator();
                Stream pOut = lData.Open(inputStream, PgpLiteralData.Binary, name, len, DateTime.Now);
                pOut.Write(data, 0, len);
                pOut.Dispose();
                lData.Close();
                bytes = tempStream.ToArray();
            }
            //
            var generator = new PgpEncryptedDataGenerator(KeyAlgorithm, false, new SecureRandom());
            generator.AddMethod(PublicKey);
            using (var encryptedOut = generator.Open(encStream, new byte[BUFFER_SIZE]))
            {
                encryptedOut.Write(bytes, 0, bytes.Length);
            }
        }

        static void Decrypt(Stream encStream, Stream decryptStream)
        {
            PgpObjectFactory pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(encStream));
            PgpObject o = pgpF.NextPgpObject();
            PgpEncryptedDataList enc;
            if (o is PgpEncryptedDataList)
            {
                enc = (PgpEncryptedDataList)o;
            }
            else
            {
                enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
            }
            PgpPublicKeyEncryptedData pbe = null;
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                pbe = pked;
                break;
            }
            PgpObjectFactory plainFact = null;
            using (Stream clear = pbe.GetDataStream(PrivateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }
            PgpObject message = plainFact.NextPgpObject();
            if (message is PgpCompressedData)
            {
                var cData = (PgpCompressedData)message;
                PgpObjectFactory of;
                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }
                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                }
                PgpLiteralData Ld = (PgpLiteralData)message;
                Stream unc = Ld.GetInputStream();
                Streams.PipeAll(unc, decryptStream);
                return;
            }
            if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, decryptStream);
                return;
            }
            if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("PgpOnePassSignatureList");
            }
            throw new PgpException("Not a simple encrypted file");
        }

        private const string _defaultPublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFr+9sYBCADMWuB8bT9XG+8ql+bLDY2qh5cmwG9xlAVHDN0TEph/gSBmXef4
sTWuPwiDGdmBtsefEdr9KJP0AglfTYXa2hi2ud0VzqIN/Fk9Rcd/T6BNXwbo6kM/
2ov5/UmQgB4MFZtMeg9u4n+qmb/t7l9P+WiGekrXMIfbFSgSGVfG2G/YtaunAFsd
7ymeAfJrhR3y09KNhmxsu79JPHA5RQQ+Q/x1buY+8GqacZ1O3jkA5ZCOtNnrFGrI
/rMt191ATHX68/WTGfqkjRk2qApTkUoVa03veLklCU7hcsWj92visMlxJbtfC80K
+4q/z5I/62AFXWQ0Sa+PDogPaghZJf5ZyHXnABEBAAG0CXNxbGJhY2t1cIkBHAQQ
AQIABgUCWv6UVgAKCRCFeOxiq6NKuh6DCAC/uBq1Iekogghjtb/3xDvHL9WCL1AA
bQoXKngp+bxkCxaeCgGUe1yf/asgxQDeK17fyW6v4+5UKqWrDlyGHuI3rc8PWvn/
pQPeRgJ8FeQGcI/I83GYNbs49FmuGksMLA1dnNVyxhMH4JbhEPk1oLeFVFj8P/II
kbTBGQt0slli2KTOTFa1NHtuYmK551I36/fdmrqqqNHKNDggrQI/qnJeb8eGgq7X
FMKBbauIej8b6Fs3QbQc3hHT2YfWYBf1+fT+UNEj3pis0SlrtinLMznsLTfs/xGI
4TrTywUzeP7HynjgHd9vi1VeN5zPZaPb5jgKexFLME8Ip0Z7g1HVZ2Ap
=jFcb
-----END PGP PUBLIC KEY BLOCK-----";
    }
}
