package subjective

func CumulativeFusionOperator(A, B OpinionT) OpinionT {

	// if A.u == 0.0 anf B.u == 0.0 {...}
	if A.u+B.u == 0.0 {
		return cumulativeFusionCase1(A, B)
	}

	// if A.u > 0.0 or B.u > 0.0 {...}
	return cumulativeFusionCase2(A, B)
}

func cumulativeFusionCase1(A, B OpinionT) OpinionT {
	var C OpinionT

	C.b = (A.b*B.u + B.b*A.u) / (A.u + B.u - A.u*B.u)

	C.u = (A.u * B.u) / (A.u + B.u - A.u*B.u)

	if A.u+B.u == 2.0 {
		C.a = (A.a + B.a) / 2
	} else {
		C.a = (A.a*B.u + B.a*A.u - (A.a+B.a)*A.u*B.u) / (A.u + B.u - 2*A.u*B.u)
	}

	return C
}

func cumulativeFusionCase2(A, B OpinionT) OpinionT {
	var gamma float32 = 0.5
	var C OpinionT

	C.b = gamma*A.b + gamma*B.b

	C.u = 0.0

	C.a = gamma*A.a + gamma*B.a

	return C
}
