using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PwdFinder
{
	class Program
	{
        #region Private variables


        // 6 chars password = 35 min
        // 5 chars password = 32 sec
        // 4 chars password = < 1 sec
        // the secret password which we will try to find via brute force
        //private const string Password = "AB3AB964804DC9AE20DE3B02D379B1BD";
        private const string Password = "bodys";
        private static string _result;
	    private const string WordList = "wordlist.txt";

	    private static bool _isMatched;

		/* The length of the charactersToTest Array is stored in a
		 * additional variable to increase performance  */
		private static int _charactersToTestLength;
		private static long _computedKeys;

		/* An array containing the characters which will be used to create the brute force keys,
		 * if less characters are used (e.g. only lower case chars) the faster the password is matched  */
		private static readonly char[] CharactersToTest =
        {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z','A','B','C','D','E',
            'F','G','H','I','J','K','L','M','N','O','P','Q','R',
            'S','T','U','V','W','X','Y','Z','1','2','3','4','5',
            '6','7','8','9','0','!','$','#','@','-','£','"', ' ',
            '&', '¤', '%', '/', '{', '(', '[', ')', ']', '=', '}',
            '+', '?', '`', ' '
        };

		#endregion

		static void Main(string[] args)
		{
			var timeStarted = DateTime.Now;
			Console.WriteLine("Start BruteForce - {0}", timeStarted);

			// The length of the array is stored permanently during runtime
			_charactersToTestLength = CharactersToTest.Length;

			// The length of the password is unknown, so we have to run trough the full search space
			var estimatedPasswordLength = 0;
            
		    foreach (var pass in GetWordList(WordList).Where(pass => pass == Password || CalculateMd5Hash(pass) == Password))
		    {
		        _isMatched = true;
		        _result = pass;
		    }

            if ((!_isMatched))
                Console.WriteLine("Did not found pass in wordlist, will now match characters");

            while (!_isMatched)
			{
				/* The estimated length of the password will be increased and every possible key for this
				 * key length will be created and compared against the password */
				estimatedPasswordLength++;
                StartBruteForce(estimatedPasswordLength);
			}

			Console.WriteLine("Password matched. - {0}", DateTime.Now);
			Console.WriteLine("Time passed: {0}s", DateTime.Now.Subtract(timeStarted).TotalSeconds);
			Console.WriteLine("Resolved password: {0}", _result);
			Console.WriteLine("Computed keys: {0}", _computedKeys);

			Console.ReadLine();
		}

        #region Private methods


        private static IEnumerable<string> GetWordList(string wordList)
        {
            if (wordList == null) return new List<string>();
            var list = new List<string>();
            const int bufferSize = 128;
            using (var fileStream = File.OpenRead(Directory.GetCurrentDirectory() + "/" + wordList))
            using (var streamReader = new StreamReader(fileStream, Encoding.UTF8, true, bufferSize))
            {
                string line;
                while ((line = streamReader.ReadLine()) != null)
                {
                    list.Add(line);
                }
            }
            return list;
        }

        /// <summary>
        /// Starts the recursive method which will create the keys via brute force
        /// </summary>
        /// <param name="keyLength">The length of the key</param>
        private static void StartBruteForce(int keyLength)
		{
			var keyChars = CreateCharArray(keyLength, CharactersToTest[0]);
			// The index of the last character will be stored for slight perfomance improvement
			var indexOfLastChar = keyLength - 1;
			CreateNewKey(0, keyChars, keyLength, indexOfLastChar);
		}

		/// <summary>
		/// Creates a new char array of a specific length filled with the defaultChar
		/// </summary>
		/// <param name="length">The length of the array</param>
		/// <param name="defaultChar">The char with whom the array will be filled</param>
		/// <returns></returns>
		private static char[] CreateCharArray(int length, char defaultChar)
		{
			return (from c in new char[length] select defaultChar).ToArray();
		}

		/// <summary>
		/// This is the main workhorse, it creates new keys and compares them to the password until the password
		/// is matched or all keys of the current key length have been checked
		/// </summary>
		/// <param name="currentCharPosition">The position of the char which is replaced by new characters currently</param>
		/// <param name="keyChars">The current key represented as char array</param>
		/// <param name="keyLength">The length of the key</param>
		/// <param name="indexOfLastChar">The index of the last character of the key</param>
		private static void CreateNewKey(int currentCharPosition, char[] keyChars, int keyLength, int indexOfLastChar)
		{
			var nextCharPosition = currentCharPosition + 1;
			// We are looping trough the full length of our charactersToTest array
			for (int i = 0; i < _charactersToTestLength; i++)
			{
				/* The character at the currentCharPosition will be replaced by a
				 * new character from the charactersToTest array => a new key combination will be created */
				keyChars[currentCharPosition] = CharactersToTest[i];

				// The method calls itself recursively until all positions of the key char array have been replaced
				if (currentCharPosition < indexOfLastChar)
				{
					CreateNewKey(nextCharPosition, keyChars, keyLength, indexOfLastChar);
				}
				else
				{
					// A new key has been created, remove this counter to improve performance
					_computedKeys++;

					/* The char array will be converted to a string and compared to the password. If the password
					 * is matched the loop breaks and the password is stored as result. */
					if ((new String(keyChars)) == Password)
					{
						if (!_isMatched)
						{
							_isMatched = true;
							_result = new String(keyChars);
						}
						return;
					}
				}
			}
		}


        private static string CalculateMd5Hash(string input)
        {
            // step 1, calculate MD5 hash from input
            var md5 = System.Security.Cryptography.MD5.Create();
            var inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            var hash = md5.ComputeHash(inputBytes);

            // step 2, convert byte array to hex string
            var sb = new StringBuilder();
            foreach (var t in hash) sb.Append(t.ToString("X2"));
            return sb.ToString();
        }


    #endregion

}
}
