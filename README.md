# Hivemind - Knowledge Revolution


Hivemind Markets (Hanson Market Maker)
--------------------------------------

Hanson Automated Market Maker:
An event must result in exactly one of n possible mutually distinct outcomes.
Each outcome is assigned a potentially unlimited number of shares which are
valued at the event's end to be either zero or one depending on which outcome
occurred. Shares are purchased or sold from a market maker which has a fixed
formula C for its account value depending solely on the number of shares
outstanding. The cost of purchasing or selling shares is the difference of this
formula before and after the transaction. That is, the total cost to buy (or
sell if the values are negative) M={M1,M2, ...,Mn} shares when there are
currently N={N1,N2,...Nn} shares outstanding is C(N+M) - C(N).

The following constraints ensure that the market maker formula C represents
meaningful prices:
  1. Probability. The price of a share is the market's indication of the
     probability of that outcome. Each term of grad C must be between zero
     and one and collectively sum to one.
  2. Convexity. Repeatedly purchasing a set of shares is increasingly more
     expensive. That is, C(N+2M) - C(N+M) >= C(N+M) - C(N).

The first two constraints suggest the consideration of the convex conjugate
of C. The convex conjugate of a function f is f^(y) = sup_x {<x,y> - f(x)}.
The difference in the braces is the difference of the graphs of z=f(x) and the
plane z=<x,y>, with the supremum occurring when y = (grad f)(x). By sliding the
plane down to be tangent of f, we have that f^ is just the negative z-intercept
of the tangent to f. The conjugate f^ is immediately seen to be convex by
expanding linear combinations of y and f(x) in the first equation. The conjugate
of the conjugate is the highest convex function sitting below f since
  f^^(x) = sup {<y,x> - f^(y)}
         = sup {<y,x> + the z-intercept of the tangents to the graph of f}.
         = highest value at x on all tangents to the graph of f.
         = f(x) if f is convex.
Likewise the x in the relations y = (grad f)(x) and x = (grad f^)(y) are the
same x and so we have (grad f^)((grad f)(x)) = x.

Hanson's market scoring rules are simply the convex conjugates of the market
maker's account formulas C and vice versa. Consider the set of probabilities
P={p1,p2,...,pn} of the outcomes such that each p is between zero and one and
together they sum to one. Any function S(P) is called a score and moreover S
is called a proper score if it is convex.  Hanson creates a rule of scoring
by the process: For each point P there is a tangent at S(P) which intersects
the n axes. Call these intersections S1(P), S2(P), ..., Sn(P).

If the probabilities {q1,q2,...,qn} are known then the expectation
E[S(P)] = S1(P)q1 + S2(P)q2 + ... + Sn(P)qn can be compared against other
scores. Now consider the convex conjugate of S, C = S^. It follows that
(grad C)((grad S)(P)) = (grad S^)((grad S)(P)) = P, and we have what we need in
order for C to be a market maker formula.

Example (Lognormal Scoring Rule):
  S(P) = b sum_i pi log pi
  Si(P) = b log pi
  C(N) = b log sum exp(Ni/b)

Scaled Markets:
For events resulting in exactly one value x in a range [a,b], the outcome set is
approximated to be n disjoint outcomes where:
  [a,a+h], [a+h,a+2h], ... , [a+(n-1)h,a+nh] where h = (b-a)/n.
Any share to be worth an increasing function of x at the event's end is
approximated with a basket of shares in each of the lower events.

TODO : Liquidity sensitive markets.


The Hivemind Vote Process (Deciding Outcomes)
----------------------------------------------

At an interval of N number of blocks known as the tau, the Hivemind vote process
is initiated by the miners. A voting period begins when the current block height
is divisible by the tau value (nHeight % tau) == 0. A voting period ends at
N + (tau - 1).

1. Voters request ballots and submit votes:

During a voting period, the voters (votecoin holders) may query for a ballot
containing the list of recently concluded decisions. Voters are obliged to vote
on the outcome of all decisions which have recently ended. The voters will first
submit a hash of their vote (containing the selected outcome or NA), with the
contents encrypted. After the voting period has ended, voters will submit
unencrypted copies of their vote(s). The hashes of the revealed (unencrypted)
votes and previously submitted sealed (encrypted) votes must match.

2. Creation of the vote matrix M:

A vote matrix M is created with dimensions [ m x n ] where m equals the number
of voters and n equals the number of decisions. Matrix M may or may not contain
votes which have an NA response. NA responses will be filled in with values from
the preliminary outcome vector.

3. Creation of the reputation vector R:

A reputation vector R is created with a single dimension [ m ] where m is equal
to the number of voters.

4. Calculation of the preliminary outcome vector:

The preliminary outcome vector is arrived at as follows:
  1) Let mi be the j-th column in M of all votes case for the j-th decision.
  2) Remove all entries of the vectors {r,mj} corresponding to NA values.
  3) Set the weights of the shortened reputation vector r by setting
  r_j = |r_j|/Sum |r_i|.
  4) The outcome is then sum r_j m_j if the decision is binary, the weighted
  median otherwise.

5. Calculation of new Reputation values:

New voter reputation values will now be calculated in the following manner:
  Let M be the [ m x n] Filled Vote Matrix and r the Reputation Vector.
  Let A be the reputation-weighted covariance matrix of M

  A_ij =
  sum_k r_k (M_ki - wgtavg(M_.i)) (M_kj - wgtavg(M_.j)) / (1 - sum_k r_k^2)
  with singular value decomposition of A = U D V^T where:
    U m x m unitary.
    D m x n diagonal matrix with nonincreasing diagonal entries.
    V n x n unitary.

  The first column u of U will be used to adjust the voters reputation values
  as follows:
    Score = V u
    Score1 = Score + |min{Score}|, New1 = Score1^T M, reweighted
    Score2 = Score - |max{Score}|, New2 = Score2^T M, reweighted
  uadj = ( ||New1 -  r^T M|| < ||New2 - r^T M|| )? Score1: Score2;
  z be defined by z_i = uadj_i * r_i / avg{r_i}.
  rr be defined by rr_i = |z_i| / sum |z_i|.

  Finally, the reputation vector R is recalculated as follows:
  R = alpha * rr  + (1 - alpha) * R.

6. Final Outcomes:

To conclude the Hivemind voting process, the final outcomes vector will be
calculated. The final calculation is the same as the preliminary calculation in
step 4, but using the new reputation vector R and the filled matrix M.




Hivemind Blockchain
===================

Bitcoin's block chain can be viewed as a ledger of actions on a dataset. The
dataset is the set of all coin allocations to addresses and the actions are
the transfers of coins from a subset of addresses to other addresses.

Hivemind is a generalization of both the dataset and the set of actions.

Hivemind's dataset consists of sets of:
   1. bitcoin allocations to public addresses
   2. votecoin allocations to public addresses
   3. branches
   4. decisions within each branch
   5. markets across a subset of decisions
   6. trades in each market
   7. sealed votes in each {branch, tau multiple}
   8. steal votes in each {branch, tau multiple}
   9. revealed votes in each {branch, tau multiple}
  10. outcomes of each decision (and hence market)

Hivemind's actions consists of:
   1. all bitcoin-type transfers of bitcoins.
   2. creation of branches (note: this is done in a very limited fashion)
   3. creation of decisions
   4. creation of markets
   5. creation of trades
   6. creation of sealed votes
   7. creation of steal votes
   8. creation of reveal votes
   9. publishing outcomes with transfers of bitcoins.
  10. redistribution of votecoin allocations

Anyone with bitcoins may initiate any of the actions 1,3,4,5. Anyone with
votecoins will be obligated to initiate actions 6,8. The miners will initiate
9 and 10.

Each hivemind-specific action is a bitcoin-like transaction where the output
script designates one of the actions to be taken. The format of the output
script is simply:

   output_script =
         OP_PUSHxXX    number of bytes
         char          action_type
         {uint8}+      action_data
         OP_MARKET     0xc0

If viewed as a stack operation, action_type and action_data are simply pushed
onto the stack and then OP_MARKET acts as an operation to (1) do the action
specified by the action_type using action_data as inputs and (2) clear the
stack with a TRUE result. The action_type byte will specify one of the
hivemind-specific actions 2-8 above.  The specific format for action_data is
as follows.



Create Branch
------------------

  action_type = char        'B' (createbranch)
  action_data = string      name
                string      description
                uint64      baseListingFee
                uint16      freeDecisions
                uint16      targetDecisions
                uint16      maxDecisions
                uint64      minTradingFee
                uint16      tau (in block numbers)
                uint16      ballotTime (in block numbers)
                uint16      unsealTime (in block numbers)
                uint32      consensusThreshold
                uint64      alpha (for smoothed reputation)
                uint64      tol (for binary decisions)

  Note 1: Each branch has its own set of votecoins. When a new branch is created,
  it is simply a many-address-to-many-address votecoin transaction along with a
  single createbranch action in the output list. The input votecoins will no
  longer be a part of their previous branches and the output votecoins will now
  be a part of the new branch.

  Note 2: Each block number ending in a multiple of tau denotes the start of a
  voting period for the branch's recently ended decisions. The schedule is

     block number / range
     -----------------------------------   -----------------------------------
     n*tau                                 ballots available for all decisions
                                              ending ((n-1)*tau, n*tau]
     (n*tau, n*tau+ballotTime]             sealed ballots may be submitted
     (n*tau, n*tau+ballotTime+unsealTime)  unsealed ballots may be submitted
     n*tau + ballotTime + unsealTime       miner runs outcome algorithm

  We must have ballotTime + unsealTime less than tau so that the change of
  votecoins in an outcome is set before the next run of the outcome algorithm.

  It is desirable to have tau correspond to approximately two weeks (for 10
  minute block spacing, tau = 2016).

  Note 3: The outcome algorithm is best when there are many decisions on a
  ballot, but not too many. The cost to create a decision for a ballot is thus
  structured to depend on how many decisions have already been created for
  that specific ballot. The parameters
       freeDecisions <= targetDecisions <= maxDecisions.
  are required.  For the N-th decision ending in (n-1)*tau, n*tau], the
  "listing fee" cost to create another decision in that interval will be

     cost                                  N
     -----------------------------------   -----------------------------------
     0                                     [0, freeDecisions)
     baseListingFee                        [freeDecisions, targetDecisions)
     (N - targetDecisions)*baseListingFee  [targetDecisions, maxDecisions)
     impossible                            [maxDecisions,infty)

  Note 4: TODO: consensusThreshold requirement for the outcome algorithm

  Note 5: TODO: minTradingFee

  Note 6: TODO: The creation of a new branch is a controlled process.


Create Decision
------------------

  action_type = char        'D' (createdecision)
  action_data = uint160     bitcoin public key
                uint256     branchid
                string      prompt
                uint32      eventOverBy (block number)
                uint8       is_scaled (0=false, 1=true)
                uint64      if scaled, minimum
                uint64      if scaled, maximum
                uint8       answer optionality (0=not optional, 1=optional)

  Note 1: The creator of the decision pays a listing fee according to the
  branch parameters and will receive a portion of the trading fees of all
  markets on that decision. The outcome algorithm will allocate 25% of
  each market's trading fees across the bitcoin public keys in the market's
  decision list.


Create Market
------------------

  action_type = char        'M' (createmarket)
  action_data = uint160     bitcoin public key
                uint64      B (liquidity parameter)
                uint64      tradingFee
                uint64      maxCommission
                string      title
                string      description
                string      tags (comma-separated strings)
                uint32      maturation (block number)
                uint256     branchid
                varint      number of decisionids
                {uint256}+  decisionids
                {uint8}+    decisionFunctionids
                uint32      txPoWh transaction proof-of-work hashid
                uint32      txPoWd transaction proof-of-work difficulty level


  Note 1: The market will be dependent on the outcome of each decision
  in the list. The maturation is set to be the maximum of the decision's
  eventOverBy numbers.

  Note 2: The market may depend on a function of the scaled decisions.
  The initial list of functions are

     id                                    f(X)
     ----------------------                ------------------
     X1 [default]                          X
     X2                                    X*X
     X3                                    X*X*X
     LNX1                                  LN(X)

  Note 3: Liquidity Sensitivity.
  The market author purchases an initial minShares shares in each of the
  N states. Those minShares will never be sold (money to be returned to the
  author upon market conclusion). The number of minShares is derived from
  the maxCommission parameter
    minShares = B log N / maxCommission.
  Before the shares are purchased the account value is
    B log sum exp(0/B)
  After the shares are purchased the account value is
    B log sum exp(minShares /B)
  The initial purchase of minShares in each state then costs
         = B log sum exp(minShares / B)               - B log sum exp(0/B)
         = B log [N exp(B log N / maxCommission / B)] - B log N
         = B log [exp(log N / maxCommission)]
         = B log [N / maxCommission]
         = minShares
  A zero maxCommission will designate the market to be "non-LS".



Create Trade
------------------

  action_type = char        'T' (createtrade)
  action_data = uint160     bitcoin public key
                uint256     marketid
                uint8       isbuy
                uint64      number of shares
                uint64      price
                uint32      decision state
                uint32      nonce



Create Reveal Vote
------------------

  action_type = char        'R' (createrevealvote)
  action_data = uint256     branchid
                uint32      height
                uint256     voteid
                varint      ndecisionids
                {uint256}+  decisionids
                {uint64}+   votes
                uint160     votecoin public key

  Note 1: The voteid is a previously submitted sealed vote.

  Note 2: voteid must match the hash of the outcome with zeros in
  place of the voteid.


Create Sealed Vote
------------------

  action_type = char        'S' (createsealedvote)
  action_data = uint256     branchid
                uint32      height
                uint256     voteid

  Note: voteid is the hash of the createrevealvote outcome with
  zeros in place of the voteid.


Create Steal Vote
------------------

  action_type = char        'L' (createstealvote)
  action_data = uint256     branchid
                uint32      height
                uint256     voteid

  Note 1: The voteid is a previously submitted sealed vote.


Create Outcome
------------------

  action_type = char        'O' (createoutcomes)
  action_data = uint256     branchid
                uint32      number of voters
                {uint64}+   old reputation
                {uint64}+   this reputation
                {uint64}+   smoothed reputation
                {uint64}+   NA row
                {uint64}+   participation row
                {uint64}+   participation rel
                {uint64}+   bonus row
                uint32      number of decisions
                {uint256}+  decision ids
                {uint64}+   is scaled array
                {uint64}+   first loading
                {uint64}+   decisions raw
                {uint64}+   consensus reward
                {uint64}+   certainty
                {uint64}+   NA column
                {uint64}+   participation column
                {uint64}+   author bonus
                {uint64}+   decisions final
                {uint64}+   vote matrix
                uint64      NA value
                uint64      alpha value
                uint64      tolerance value
                tx          payout / reputation transaction

  action_type = char        'R' (redistribution of votecoins)
  action_data = varint      noutputs
                {output}+   output array (pay-to-pubkey-hash)
