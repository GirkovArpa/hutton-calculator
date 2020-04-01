'use strict';

/**
 * Sanitize inputs (specifically, the password and key).
 * @param {...object} inputs - The strings to be returned as lowercase letters.
 * @returns {array} An array of sanitized inputs.
 */
const sanitizeInputs = (...inputs) => inputs.map((text = '') => text.toString()
  .toLowerCase()
  .replace(/[^a-z]/g, ''));

/**
 * Return an alphabet shuffled with the provided key.
 * @param {string} key - The key to use.
 * @returns {array} The shuffled alphabet as an array.
 */
const keyAlphabet = (key = '') => [...new Set(key.split('').concat('abcdefghijklmnopqrstuvwxyz'.split('')))];

/**
 * The Hutton cipher, invented by u/EricBondHutton, reknowned for its security and ease of use as a hand cipher.
 * @param {number} version - The version of the cipher to use. v1 has a known flaw (corrected by u/GirkovArpa with the approval of its inventor) and such a ciphertext was cracked through the application of brute force by u/AreARedCarrot (for which he won an award of £1000), but both are unbroken.
 * @param {string} input - The text to encrypt or decrypt.
 * @param {string} password - The password to use.
 * @param {string} key - The key to use for shuffling the alphabet.
 * @param {boolean} decrypt - Whether to decrypt instead of encrypt.
 * @returns {string} The processed text.
 */
const hutton = (version = 2, input = '', password = '', key = '', decrypt = false) => {
  [password, key] = sanitizeInputs(password, key);
  password = password.repeat(Math.ceil(input.replace(/[^A-Za-z]/g, '').length / password.length)).split('');
  input = input.toString().split('');
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  let alphabetKeyed = keyAlphabet(key);
  const alphabetKeyedConstant = alphabetKeyed.join('').toUpperCase();
  let output = '';
  for (let i = 0; i < input.length; i++) {
    if (!/[A-Za-z]/.test(input[i])) {
      output += input[i];
      password.splice(i, 0, '');
      continue;
    }
    let upperCase = /[A-Z]/.test(input[i]);
    if (upperCase) {
      input[i] = input[i].toLowerCase();
    }
    let shift = alphabet.indexOf(password[i]) + 1;
    if (version === 2) {
      shift += alphabet.indexOf(alphabetKeyed[0]) + 1;
    }
    if (decrypt) {
      shift = -shift;
    }
    let outputLetterIndex = (shift + alphabetKeyed.indexOf(input[i])) % alphabet.length;
    if (decrypt) {
      outputLetterIndex = (outputLetterIndex + alphabet.length) % alphabet.length;
    }
    let outputLetter = alphabetKeyed[outputLetterIndex];
    if (upperCase) {
      outputLetter = outputLetter.toUpperCase();
    }
    output += outputLetter;
    let alphabetKeyedIndex = alphabetKeyed.indexOf(input[i]);
    [alphabetKeyed[outputLetterIndex], alphabetKeyed[alphabetKeyedIndex]] = [alphabetKeyed[alphabetKeyedIndex], alphabetKeyed[outputLetterIndex]];
  }
  //return output;
  return { output, alphabet: alphabetKeyedConstant };
}