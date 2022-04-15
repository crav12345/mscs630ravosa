/**
 * file: Driver_lab5.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 5
 * due date: March 6, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab5 program which provides data for testing
 * the complete implementation of the Advanced Encryption Standard (AES)
 * in the AESCipher.java program.
 */

package src;

import java.util.Scanner;

import static src.AESCipher.*;

/**
 * Driver_lab5
 *
 */
public class Driver_lab5 {
    /**
     * main
     *
     * Parameters:
     *   args: command line arguments
     *
     * Return value: none.
     */
    public static void main(String[] args) {
        // The 16 hex character representation of the system key.
        String keyHex;

        // The 16 hex character plaintext.
        String pTextHex;

        // The ciphertext created with AES.
        String cTextHex;

        // Prompt user to input key hex and make sure it's in uppercase.
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter key hex (a 16 hex character string): ");
        keyHex = sc.nextLine().toUpperCase();
        System.out.print("Enter the plaintext hex (a 16 hex character string): ");
        pTextHex = sc.nextLine().toUpperCase();
        sc.close();

        // Encrypt the plaintext and report the ciphertext.
        cTextHex = aes(pTextHex, keyHex);
        System.out.println("\n" + cTextHex);

        // For testing, use key: 5468617473206D79204B756E67204675
        // For testing, use p: 54776F204F6E65204E696E652054776F
    }
}
