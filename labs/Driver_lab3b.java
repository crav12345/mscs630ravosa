/**
 * file: Driver_lab3b.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 3
 * due date: February 7, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab3b program converts a plaintext to several
 * hexadecimal matrices of dimensions 4x4.
 */

package src;

import java.util.Scanner;

/**
 * Driver_lab3b
 *
 * This class accepts a user plaintext and encrypts it to a series of
 * hexadecimal matrices.
 */
public class Driver_lab3b {
    /**
     * main
     *
     * This function accepts from the user a substitution character and a
     * plaintext message. The plaintext is broken into substrings of 16 or
     * fewer characters. Each substring is then encoded to a 4x4 matrix of
     * hexadecimals using the getHexMatP() method.
     *
     * Parameters:
     *   args: command line arguments
     *
     * Return value: none.
     */
    public static void main(String[] args) {
        // User specified substitution character.
        char s;
        // User specified plaintext.
        String p;
        // Variable used to specify character length of splits in p.
        int n = 16;
        // Array to store plaintext at lengths of n characters.
        String[] substringsP;
        // Stores result matrix of individual substrings in p.
        int[][] result;

        // Gather substitution character and plaintext from user.
        Scanner sc = new Scanner(System.in);
        System.out.print("Input substitution character: ");
        s = sc.nextLine().charAt(0);
        System.out.print("Input plaintext: ");
        p = sc.nextLine();
        sc.close();

        // Split the plaintext into strings of n characters.
        substringsP = p.split("(?<=\\G.{" + n + "})");

        // Get the hex matrices for each substring.
        for (int i = 0; i < substringsP.length; i++){
            System.out.println();

            result = getHexMatP(s, substringsP[i]);

            // Print the result matrix for the current substring.
            for (int row = 0; row < result.length; row++) {
                for (int col = 0; col < result.length; col++) {
                    System.out.print(
                            Integer.toHexString(result[row][col]) + " "
                    );
                }
                System.out.println();
            }
        }
    }

    /**
     * getHexMatP
     *
     * This method converts a string into a 4x4 matrix of integers. If the
     * string is less than 16 characters, empty indices in the matrix are
     * replaced with an integer representation of the provided substitution
     * character, x.
     *
     * Parameters:
     *   x: the substitution character
     *   y: the plaintext which is encoded into the matrix
     *
     * Return value: a 2D matrix of integer representations of characters.
     */
    public static int[][] getHexMatP(char x, String y) {
        int[][] hexMat = new int[4][4];
        int hexMatSize = 16;
        int row = 0, col = 0;

        // Iterate through all indices of the hex matrix.
        for (int i = 0; i < hexMatSize; i++) {
            // If a character exists at this index in the string, add it to
            // the hex matrix.
            if (i < y.length())
                hexMat[row++][col] = y.charAt(i);
            // If a character doesn't exist at this index, add the substitution
            // character to the matrix.
            else
                hexMat[row++][col] = x;

            // If we've reached the end of a row, go back to the top of the
            // matrix and advance to the next column.
            if (row == hexMat.length) {
                row = 0;
                col++;
            }
        }
        return hexMat;
    }
}
