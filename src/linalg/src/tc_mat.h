/*
 * Copyright (c) 2015 The Hivemind Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef HIVEMIND_LINALG_MAT_H
#define HIVEMIND_LINALG_MAT_H

#include <stdint.h>

struct tc_mat {
    double **a;
    uint32_t nr, nc;
};

/**
 * Create a matrix.
 * Return tc_mat matrix if successful.
 */
struct tc_mat *tc_mat_ctr(uint32_t nr_, uint32_t nc_);

/**
 * Delete a matrix.
 */
void tc_mat_dtr(struct tc_mat *);

/**
 * Clear (reset) a matrix.
 */
void tc_mat_clear(struct tc_mat *);

/**
 * Printf() a matrix.
 */
void tc_mat_print(const struct tc_mat *);

/**
 * Calculate the Norm of a matrix.
 * Return Norm if successful, return 0.0 if error (or if the matrix is empty).
 */
double tc_mat_norm(const struct tc_mat *);

/**
 * Clear and resize matrix at pointer.
 */
void tc_mat_resize(struct tc_mat *, uint32_t nr_, uint32_t nc_);

/**
 * Copy contents and size of second matrix to first.
 */
void tc_mat_copy(struct tc_mat *, const struct tc_mat *);

/**
 * Convert matrix into identity matrix.
 */
void tc_mat_identity(struct tc_mat *);

/**
 * Transpose a matrix. Saves transposed matrix in the first pointer.
 */
void tc_mat_transpose(struct tc_mat *, const struct tc_mat *);

/**
 * Add matrix A & B, save result in first pointer.
 * Return 0 if successful, -1 if error.
 */
int tc_mat_add(struct tc_mat *, const struct tc_mat *A, const struct tc_mat *B);

/**
 * Subtract matrix A & B, save result in first pointer.
 * Return 0 if successful, -1 if error.
 */
int tc_mat_sub(struct tc_mat *, const struct tc_mat *A, const struct tc_mat *B);

/**
 * Multiply matrix A & B, save result in first pointer.
 * Return 0 if successful, -1 if error.
 */
int tc_mat_mult(struct tc_mat *, const struct tc_mat *A, const struct tc_mat *B);

/**
 * Perform scalar multiplication, based on param 'a', save result in first
 * pointer
 * Return 0 if successful, -1 if error.
 */
int tc_mat_mult_scalar(struct tc_mat *, double a, const struct tc_mat *B);

/**
 * Perform Householder transformation to decompose matrix. Decomposes into
 * matrices U, B and V.
 * Return 0 if successful, -1 if error.
 */
int tc_mat_bidiag_decomp(const struct tc_mat *A, struct tc_mat *U, struct tc_mat *B, struct tc_mat *V);

/**
 * Find the eigenvalues in matrix A and save them in matrix E.
 * Return 0 if successful, -1 if error.
 */
int tc_mat_eigenvalues(struct tc_mat *E, const struct tc_mat *A);

/**
 * Performs Wilkinson shift and returns the result.
 * Return result if successful, 0.0 if error.
 */
double tc_mat_wilkinson_shift(const struct tc_mat *A);

/**
 * Perform singular value decomposition on matrix A saving results in pointers.
 * Return 0 if successful, -1 if error.
 */
int tc_mat_svd(const struct tc_mat *A, struct tc_mat *U, struct tc_mat *D, struct tc_mat *V);

/**
 * Normalize weighted matrix
 */
void tc_wgt_normalize(struct tc_mat *wgt);

/**
 * Perform principal component analysis, save loadings and scores in pointers.
 * Return 0 if successful, -1 if error.
 */
int tc_wgt_prin_comp(const struct tc_mat *wgt, const struct tc_mat *M,
    struct tc_mat *loadings, struct tc_mat *scores);

#define TC_VOTE_NCOLS           9
#define TC_VOTE_NROWS           7

#define TC_VOTE_OLD_REP         0
#define TC_VOTE_THIS_REP        1
#define TC_VOTE_SMOOTHED_REP    2
#define TC_VOTE_NA_ROW          3
#define TC_VOTE_PARTIC_ROW      4
#define TC_VOTE_PARTIC_REL      5
#define TC_VOTE_ROW_BONUS       6

#define TC_VOTE_IS_BINARY       0
#define TC_VOTE_FIRST_LOADING   1
#define TC_VOTE_DECISIONS_RAW   2
#define TC_VOTE_CONSENSUS_REW   3
#define TC_VOTE_CERTAINTY       4
#define TC_VOTE_NA_COL          5
#define TC_VOTE_PARTIC_COL      6
#define TC_VOTE_AUTHOR_BONUS    7
#define TC_VOTE_DECISIONS_FINAL 8

struct tc_vote {
    struct tc_mat *M; /* Vote Matrix */
    struct tc_mat *cvecs[TC_VOTE_NCOLS]; /* column (Decision) vectors */
    struct tc_mat *rvecs[TC_VOTE_NROWS]; /* row (Voter) vectors */
    double NA;
    double alpha;
    double tol;
    uint32_t nr, nc;
};

/**
 * Create vote struct.
 * Return tc_vote if successful.
 */
struct tc_vote *tc_vote_ctr(uint32_t nr, uint32_t nc);

/**
 * Delete vote.
 */
void tc_vote_dtr(struct tc_vote *);

/**
 * Return 0 if vote is valid, -1 if not valid (error).
 */
int tc_vote_notvalid(const struct tc_vote *);

/**
 * Print vote matrix; print row(s), print column(s).
 * Return 0 if successful, -1 if error (Vote does not exist).
 */
int tc_vote_print(const struct tc_vote *);

/**
 * Perform the entire hivemind vote process.
 * Return 0 if successful, -1 if error.
 */
int tc_vote_proc(struct tc_vote *);

#endif /* HIVEMIND_LINALG_MAT_H */
