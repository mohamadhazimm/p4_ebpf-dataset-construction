# Sliver console scripts (drafts)

These `.rc` files are the command spec for the testbed. They are **drafts**: the exact flag names of a few
`generate`/listener commands are confirmed live at the approved **Sink-setup** phase (by running
`sliver-client <cmd> --help` on the Sink) before anything is frozen. Nothing here has run.

How they are used:

- The Sliver server runs as a daemon on the Sink: `sliver-server daemon -l 127.0.0.1 -p 31337` (operator gRPC on
  localhost only; the C2 listeners bind `10.0.0.1` on the sealed malnet).
- An operator config is generated once: `sliver-server operator -l 127.0.0.1 -p 31337 -n hazim -P all -s op.cfg`.
- `setup.rc` runs once via `sliver-client --config op.cfg --rc setup.rc`: it starts the C2 listeners and
  generates one named implant per transport into the lab implants directory.
- `task.rc` runs per implant during its 5-minute window via `sliver-client --config op.cfg --rc task.rc` (the
  collect driver substitutes the implant selector). It issues the fixed benign task list, then returns.

Everything binds or targets `10.0.0.1` on malnet. No command here reaches outside the sealed network.
