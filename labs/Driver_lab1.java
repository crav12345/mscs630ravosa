/**
 * file: Driver_lab1.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 1
 * due date: January 23, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab1 program which runs a simple encryption
 * algorithm on a message provided by the user.
 */

package src;

import java.util.Scanner;

/**
 * Driver_lab1
 *
 * This class accepts user input and runs a very simple encryption method on
 * the provided input.
 */
public class Driver_lab1 {
  /**
  * main
  *
  * This function accepts user input and utilizes a helper method to
  * associate each character in the input message with an index in the
  * alphabet. This essentially encrypts the message, although it's quite an
  * easy encryption to break.
  *
  * Parameters:
  *   args: command line arguments
  *
  * Return value: none.
  */
  public static void main(String[] args) {
    // Used to store a user's plaintext message.
    String msg = "";

    // Used to store the encrypted message.
    int[] cypherText;

    // Prompt user for an input message.
    Scanner sc = new Scanner(System.in);
    System.out.print("Enter a message to encrypt:");
    msg = sc.nextLine();
    sc.close();

    // Encrypt the message.
    cypherText = str2int(msg);

    // Print the encrypted value of each character in the cyphertext.
    for (int index: cypherText) {
        System.out.print(index + " ");
    }
  }

  /**
   * str2int
   *
   * This function converts the characters in a string to an index ranging
   * from 0-26. These indices correspond to a letter in the alphabet where
   * 26 is equivalent to a blank space. This is used for encrypting an input
   * message.
   *
   * Parameters:
   *   plainText: the string which will be encrypted
   *
   * Return value: an array of integers representing characters.
   */
  public static int[] str2int(String plainText) {
      // The encrypted string which is returned.
      int[] cypherText = new int[plainText.length()];

      // Used to map characters to an index in the alphabet.
      String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

      // Iterate through every character in plainText.
      for (int i = 0; i < plainText.length(); i++) {
        // Find each character's index in the alphabet.
        cypherText[i] = alphabet
          .indexOf(Character.toUpperCase(plainText.charAt(i)));
      }

      return cypherText;
  }
}
