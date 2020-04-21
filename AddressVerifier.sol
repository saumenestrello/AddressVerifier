pragma solidity <0.7.0;

contract AddressVerifier {
    
    address private owner;
    address issuer;
    mapping(address => bool) public verifiedAddresses;
    
    event AddressVerified(address verifiedAddress);
    
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    
    modifier isOwner() {
        require(msg.sender == owner, "only contract owner can call this function");
        _;
    }
    
    constructor() public {
        owner = msg.sender;
        emit OwnerChanged(address(0), owner);
    }
    
    function changeOwner(address newOwner) public isOwner {
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

   
    function verify(address newAddress, bytes32 hash, bytes memory sig) public {
       uint8 v;
       bytes32 r;
       bytes32 s;
       address signer;

       (v, r, s) = parseSignature(sig);
       signer = ecrecover(hash,v,r,s);
      
       require(issuer == signer,"invalid signature");
       emit AddressVerified(newAddress);
       verifiedAddresses[newAddress] = true;
       
    }
    
    function parseSignature(bytes memory sig)
       public
       pure
       returns (uint8, bytes32, bytes32)
   {
       require(sig.length == 65,"invalid signature");
       
       bytes32 r;
       bytes32 s;
       uint8 v;

       assembly {
           // first 32 bytes, after the length prefix
           r := mload(add(sig, 32))
           // second 32 bytes
           s := mload(add(sig, 64))
           // final byte (first byte of the next 32 bytes)
           v := byte(0, mload(add(sig, 96)))
       }

       return (v, r, s);
   }

}