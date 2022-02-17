/**
 * file: Driver_lab4.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 4
 * due date: February 20, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab4 program which provides data for testing
 * the aesRoundKeys() method in the AESCipher.java program.
 */

package src;

import java.util.Scanner;

/**
 * Driver_lab4
 *
 * This class accepts a key hex from a user and generates 11 round keys by
 * calling the aesRoundKeys() method from the AESCipher class.
 */
public class Driver_lab4 {
    /**
     * main
     *
     * This function accepts a key hex input from the user and assumes the key
     * hex to be a string of 16 hex characters. The method then invokes the
     * aesRoundKeys() method from the AESCipher class to generate 11 round
     * keys according to AES key expansion.
     *
     * Parameters:
     *   args: command line arguments
     *
     * Return value: none.
     */
    public static void main(String[] args) {
        // The 16 hex character representation of the system key.
        String keyHex;
        // Var used to store the 11 round keys from the aesRoundKeys() call.
        String[] roundKeysHex;

        // Prompt user to input key hex and make sure it's in uppercase.
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter key hex (a 16 hex character string): ");
        keyHex = sc.nextLine().toUpperCase();
        sc.close();

        System.out.println();

        // Retrieve round keys.
        roundKeysHex = AESCipher.aesRoundKeys(keyHex);

        // Each element of roundKeysHex should contain 16 hex characters
        // corresponding to each round key. Results are reported here.
        for (String roundKey : roundKeysHex) {
            System.out.println(roundKey);
        }
    }
}
