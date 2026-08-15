using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Helpers
{
    internal class CombineArrays
    {
        public static byte[] Combine(params byte[][] arrays)
        {
            int len = arrays.Sum(a => a.Length);
            byte[] result = new byte[len];
            int offset = 0;

            foreach (var arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }

            return result;
        }
    }
}
