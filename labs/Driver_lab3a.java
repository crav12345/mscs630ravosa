/**
 * file: Driver_lab3a.java
 * author: Christopher Ravosa
 * course: MSCS 630L
 * assignment: lab 3
 * due date: February 7, 2022
 * version: 1.0
 *
 * This file contains the Driver_lab3a program which implements a cofactor
 * expansion algorithm to find the determinant of a matrix.
 */

package src;

import java.util.Scanner;

/**
 * Driver_lab3a
 *
 * This class accepts an NxN matrix from the user and finds its determinant via
 * the cofModDet() method. The determinant is placed in modulo m which is
 * specified by the user.
 */
public class Driver_lab3a {
    /**
     * main
     *
     * This function accepts a modulo 'm' and a matrix 'A' from the user. It
     * uses the cofModDet() method to find the matrix's determinant and place
     * it in modulo m.
     *
     * Parameters:
     *   args: command line arguments
     *
     * Return value: none.
     */
    public static void main(String[] args) {
        // Vars to store mod, matrix size, and matrix values.
        int m;
        int n;
        int[][] A;

        Scanner sc = new Scanner(System.in);

        // Acquire modulus and matrix size from user.
        System.out.print("Input modulus: ");
        m = sc.nextInt();
        System.out.print("Input matrix size: ");
        n = sc.nextInt();

        // The matrix must be the size specified by user.
        A = new int[n][n];

        // Fill the matrix with user input.
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                System.out.print("Value at matrix[" + i + "][" + j + "]:");
                A[i][j] = sc.nextInt();
            }
        }

        sc.close();

        // Find and report determinant in modulo m.
        System.out.println(cofModDet(m, A));
    }

    /**
     * cofModDet
     *
     * This function receives an integer m > 0, a matrix A, and returns the
     * corresponding determinant in modulo m as an integer.
     *
     * Parameters:
     *   m: an integer > 0
     *   A: a two-dimensional array
     *
     * Return value: an int containing the determinant of the matrix A.
     */
    public static int cofModDet(int m, int[][] A) {
        // Shorthand variable for matrix size.
        int n = A.length;

        // Var used to reduce number of return statements.
        int determinant = 0;

        // Var used to specify whether we add or subtract from determinant.
        int sign = 1;

        // If the matrix is 1x1, the determinant is the value at (0,0).
        if (n == 1)
            determinant = A[0][0];
        // We can just run this formula if the matrix is 2x2.
        else if (n == 2)
            determinant = A[0][0]*A[1][1] - A[0][1]*A[1][0];
        // This block is used for larger matrices.
        else {
            // Iterate through each element of the top row.
            for (int col = 0; col < n; col++) {
                // Find the cofactor of the current element.
                int[][] cof = getCofactor(A, 0, col);

                // Multiply this element by determinant of its cofactor.
                // Then add or subtract it to the determinant based on column.
                determinant += sign * A[0][col] * cofModDet(m, cof);

                // If we just subtracted, we want to add and vice versa.
                sign = -sign;
            }
        }

        // Put the determinant in modulo m.
        determinant = determinant % m;

        // Due to Java language specifications, if the result is negative then
        // we need to add the divisor back into the determinant.
        if (determinant < 0)
            determinant+=m;

        // Kick this determinant back up the chain.
        return determinant;
    }

    /**
     * getCofactor
     *
     * This function recieves a matrix A, an int specifying a row in A, and an
     * int specifying a column in A. The specified row and column are ignored
     * and the remaining elements of A are used to construct a cofactor.
     *
     * Parameters:
     *   A: a two-dimensional array
     *   currentRow: an integer >= 0
     *   currentCol: an integer >= 0
     *
     * Return value: a matrix containing the cofactor of an element in A.
     */
    static int[][] getCofactor(int[][] A, int currentRow, int currentCol) {
        // Shorthand variable for matrix size.
        int n = A.length;

        // This matrix will store our cofactor.
        int[][] cof = new int[n - 1][n - 1];

        // Vars to indicate which index we will use next in the cof matrix.
        int cofRow = 0;
        int cofCol = 0;

        // Iterate through every index in the provided matrix.
        for (int row = 0; row < n; row++) {
            for (int col = 0; col < n; col++) {
                // If the current index is not in the same row and column as
                // the element whose cofactor we are finding, we add it to the
                // cof matrix.
                if (row != currentRow && col != currentCol) {
                    cof[cofRow][cofCol] = A[row][col];

                    // Indicate that we will proceed to the next column in cof.
                    cofCol++;

                    // If we've reached the end of a cof column, go to the next
                    // row and move back to the first column.
                    if (cofCol == n - 1) {
                        cofCol = 0;
                        cofRow++;
                    }
                }
            }
        }

        // We've finished constructing our cofactor and can return it.
        return cof;
    }
}
