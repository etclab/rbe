package rbe

import (
	"fmt"
	"log"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe/proto"
)

//https://asecuritysite.com/golang/circl_pairing

type Ciphertext struct {
	ct0 *bls.G1
	ct1 *bls.Gt
	ct2 *bls.G2
	ct3 *bls.Gt
}

func (ct *Ciphertext) String() string {
	sb := new(strings.Builder)

	sb.WriteString("Ciphertext: {")
	fmt.Fprintf(sb, "\tct0: %v,\n", ct.ct0)
	fmt.Fprintf(sb, "\tct1: %v,\n", ct.ct1)
	fmt.Fprintf(sb, "\tct2: %v,\n", ct.ct2)
	fmt.Fprintf(sb, "\tct3: %v,\n", ct.ct3)

	return sb.String()
}

func (ct *Ciphertext) FromoProto(protoCt *proto.Ciphertext) {
	ct.ct0 = new(bls.G1)
	err := ct.ct0.SetBytes(protoCt.GetCt0().GetPoint())
	if err != nil {
		log.Fatalf("error setting ct0: %v", err)
	}

	ct.ct1 = new(bls.Gt)
	err = ct.ct1.UnmarshalBinary(protoCt.GetCt1().GetPoint())
	if err != nil {
		log.Fatalf("error unmarshaling ct1: %v", err)
	}

	ct.ct2 = new(bls.G2)
	err = ct.ct2.SetBytes(protoCt.GetCt2().GetPoint())
	if err != nil {
		log.Fatalf("error setting ct2: %v", err)
	}

	ct.ct3 = new(bls.Gt)
	err = ct.ct3.UnmarshalBinary(protoCt.GetCt3().GetPoint())
	if err != nil {
		log.Fatalf("error unmarshaling ct3: %v", err)
	}
}

func (ct *Ciphertext) ToProto() *proto.Ciphertext {
	ct1Bytes, err := ct.ct1.MarshalBinary()
	if err != nil {
		log.Fatalf("error marshaling ct1: %v", err)
	}

	ct3Bytes, err := ct.ct3.MarshalBinary()
	if err != nil {
		log.Fatalf("error marshaling ct3: %v", err)
	}

	ct0 := &proto.G1{Point: ct.ct0.Bytes()}
	ct1 := &proto.Gt{Point: ct1Bytes}
	ct2 := &proto.G2{Point: ct.ct2.Bytes()}
	ct3 := &proto.Gt{Point: ct3Bytes}

	return &proto.Ciphertext{Ct0: ct0, Ct1: ct1, Ct2: ct2, Ct3: ct3}
}

func Encrypt(pp *PublicParams, recvId int, msg *bls.Gt) *Ciphertext {
	hParamsG1 := pp.crs.hParamsG1
	hParamsG2 := pp.crs.hParamsG2

	pp.CheckIdRange(recvId)

	// block index
	k := pp.IdToBlock(recvId)
	recvBar := pp.IdToIdBar(recvId)

	g2 := pp.g2
	com := pp.Commitments[k]

	r := randomScalar()

	ct0 := com

	ct1 := bls.Pair(com, hParamsG2[pp.blockSize-1-recvBar])
	ct1.Exp(ct1, r)

	ct2 := new(bls.G2)
	ct2.ScalarMult(r, g2)

	ct3 := bls.Pair(hParamsG1[recvBar], hParamsG2[pp.blockSize-1-recvBar])
	ct3.Exp(ct3, r)
	ct3.Mul(ct3, msg)

	return &Ciphertext{ct0, ct1, ct2, ct3}
}
