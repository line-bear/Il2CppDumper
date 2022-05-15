using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Il2CppDumper
{
    public partial class MetadataDecryption
    {
        private static byte XorCombine(byte[] input, int offset, int size = 16)
        {
            byte ret = 0;
            for (int i = offset; i < offset + size; i++)
                ret ^= input[i];
            return ret;
        }

        private static void CompressKey(byte[] data, byte[] key)
        {
            for (int i = 0; i < 0xB0; i++)
                key[i] = XorCombine(data, 16 * i);
        }

        // this is mostly the same algorithm as in blkstuff
        // except i can't just hardcode some of the stuff since the key changes between versions this time
        // the modifications made come from a tool to decrypt metadata that already exists,
        // since i'm too much of a dumbass to figure out how the key data gets derived myself
        private static void NotBlkKeyScramble(byte[] key, byte[] data, int offset)
        {
            for (int i = 0; i < 16; i++)
                data[i + offset] ^= key[i];

            byte[] indexScramble = new byte[]
            {
                0,  13, 10, 7,
                4,  1,  14, 11,
                8,  5,  2,  15,
                12, 9,  6,  3
            };
            uint[] scratch = new uint[4];
            byte[] scratchByte = new byte[16]; // c# so no pointer casting
            for (int i = 1; i < 10; i++)
            {
                // avoid reallocating
                for (int j = 0; j < 4; j++)
                    scratch[j] = 0;
                for (int j = 0; j < 4; j++)
                {
                    scratch[j] ^= BlkStuff1p2[data[indexScramble[4 * j + 0] + offset]];
                    scratch[j] ^= BlkStuff1p3[data[indexScramble[4 * j + 1] + offset]];
                    scratch[j] ^= BlkStuff1p4[data[indexScramble[4 * j + 2] + offset]];
                    scratch[j] ^= BlkStuff1p5[data[indexScramble[4 * j + 3] + offset]];
                }
                Buffer.BlockCopy(scratch, 0, scratchByte, 0, scratchByte.Length);
                for (int j = 0; j < 16; j++)
                    data[j + offset] = (byte)(scratchByte[j] ^ key[16 * i + j]);
            }

            for (int i = 0; i < 16; i++)
            {
                byte t = data[indexScramble[i] + offset];
                scratchByte[i] = (byte)(BlkStuff1p6[t] ^ ~t);
            }

            for (int i = 0; i < 16; i++)
                data[i + offset] = (byte)(scratchByte[i] ^ key[160 + i]);
        }

        // the original metadata decryption tool also decrypted string literals with this step
        // but since i already have an implementation of that stuff used elsewhere (and because c# won't let me cast pointers),
        // this will just return the required data
        public struct StringDecryptionData
        {
            public uint stringCountXor;
            public uint stringOffsetXor;
            public uint stringLiteralOffsetXor;
            public uint stringLiteralDataCountXor;
            public uint stringLiteralDataOffsetXor;
            public byte[] stringDecryptionBlob;
        }
        private static StringDecryptionData DecryptMetadataStringInfo(byte[] metadata)
        {
            var data = new StringDecryptionData();

            var values = new uint[0x12];
            Buffer.BlockCopy(metadata, 0x60,  values, 0,  16);
            Buffer.BlockCopy(metadata, 0x140, values, 16, 16);
            Buffer.BlockCopy(metadata, 0x100, values, 32, 16);
            Buffer.BlockCopy(metadata, 0xF0,  values, 48, 8);
            Buffer.BlockCopy(metadata, 0x8,   values, 56, 16);

            ulong seed = ((ulong)values[values[0] & 0xF] << 32) | values[(values[0x11] & 0xF) + 2];
            var rand = new MT19937_64(seed);

            data.stringCountXor = (uint)rand.Int63();
            data.stringOffsetXor = (uint)rand.Int63();
            rand.Int63();
            data.stringLiteralOffsetXor = (uint)rand.Int63();
            data.stringLiteralDataCountXor = (uint)rand.Int63();
            data.stringLiteralDataOffsetXor = (uint)rand.Int63();

            var stringDecryptionBlob = new ulong[0x5000 / 8];
            for (int i = 0; i < stringDecryptionBlob.Length; i++)
                stringDecryptionBlob[i] = rand.Int63();
            data.stringDecryptionBlob = new byte[0x5000];
            Buffer.BlockCopy(stringDecryptionBlob, 0, data.stringDecryptionBlob, 0, 0x5000);

            return data;
        }

        private static void DecryptMetadataBlocks(byte[] metadata)
        {
            byte[] footer = new byte[0x4000];
            Buffer.BlockCopy(metadata, metadata.Length - footer.Length, footer, 0, footer.Length);

            if (footer[0xC8] != 0x2E ||
                footer[0xC9] != 0xFC ||
                footer[0xCA] != 0xFE ||
                footer[0xCB] != 0x2C)
                throw new ArgumentException("*((uint32_t*)&footer[0xC8]) != 0x2CFEFC2E");

            byte[] out1 = new byte[0xB00];
            byte[] out2 = new byte[0x10];
            ushort offset = (ushort)((footer[0xD3] << 8) | footer[0xD2]);
            Buffer.BlockCopy(footer, offset, out2, 0, out2.Length);
            Buffer.BlockCopy(footer, offset + 0x10, out1, 0, out1.Length);

            for (int i = 0; i < 0x10; i++)
                out2[i] ^= footer[0x3000 + i];
            for (int i = 0; i < 0xB00; i++)
                out1[i] ^= (byte)(footer[0x3010 + i] ^ out2[i % 0x10]);

            byte[] temp = new byte[0x10];
            byte[] scratch = new byte[0x10];

            byte[] hardKey = new byte[]
            {
                0xAD, 0x2F, 0x42, 0x30, 0x67, 0x04, 0xB0, 0x9C, 0x9D, 0x2A, 0xC0, 0xBA, 0x0E, 0xBF, 0xA5, 0x68
            };
            byte[] key = new byte[0xB0];
            CompressKey(out1, key);

            var entrySize = (metadata.Length / 0x100) / 0x40 * 0x40;
            for (int k = 0; k < 0x100; k++)
            {
                var off = k * entrySize;

                for (int i = 0; i < 16; i++)
                    temp[i] = (byte)(out2[i] ^ hardKey[i]);

                for (int i = 0; i < 0x40; i += 0x10)
                {
                    Buffer.BlockCopy(temp, 0, scratch, 0, 0x10);
                    Buffer.BlockCopy(metadata, off + i, temp, 0, 0x10);
                    NotBlkKeyScramble(key, metadata, off + i);
                    for (int j = 0; j < 0x10; j++)
                        metadata[off + i + j] ^= scratch[j];
                }
            }
        }

        public static StringDecryptionData DecryptMetadata(byte[] metadata)
        {
            DecryptMetadataBlocks(metadata);
            return DecryptMetadataStringInfo(metadata);
        }
    }
}
