# Base58's Taproot Class (Nov)

These are the notes + exercises that we went through in the November 2023 Taproot class for Base58.

Note that to run the `bitcoin-core` examples, you'll need bitcoind running.

This repository includes a nix flake which will setup all the required dependencies to run this notebook + bitcoin core.

## To load the nix environment.

You'll nix installed locally. Generally, you can do this with the following command

	curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install


Check out the instructions on the [Zero to Nix installer](https://zero-to-nix.com/concepts/nix-installer) if you 
need help or more of a walk through.


Once nix in on your machine, you should be able to load everything you need for this notebook with `nix develop`.


## Running bitcoin core

You'll need to have bitcoin-core running on regtest for the `!bitcoin-cli -regtest` jupyter notebook cells to work.

Before you start the notebook, you should start up bitcoin-core on regtest. You can do that with the following command.
Run this inside the shell you just started with `nix develop`, above.

	bitcoind -regtest -daemon -fallbackfee=0.00000012


Once bitcoin-core is up and running, you're ready to start the jupyter notebook.

## Running juptyer

Should be very simple. Just call the following from inside the nix develop environment.

	jupyter notebook


## Shutting everything down

To shut down bitcoind, run 

	bitcoin-cli -regtest stop

To get out of the nix develop environment, run

	exit



## Authors

@niftynei is mainly responsible.

Huge thanks to @realeinherjar for the working nix flake!


Check out the next base58 classes: [website](https://base58.school)
Stay up to date with what we're doing via [our twitter](https://twitter.com/base58btc)
