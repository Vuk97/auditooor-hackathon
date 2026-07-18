# @version 0.3.7
# A Vyper bytes4->address route map written with no collision reject.
# GEN-EL2 must FIRE (router-map, no-add-collision-require).

routes: public(HashMap[bytes4, address])

@external
def register(selector: bytes4, impl: address):
    self.routes[selector] = impl
