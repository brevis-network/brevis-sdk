package utils

// FlipByGroups flips the order of the groups of groupSize. e.g. [1,2,3,4,5,6] with groupSize 2 is flipped to [5,6,3,4,1,2]
func FlipByGroups[T any](in []T, groupSize int) []T {
	res := make([]T, len(in))
	copy(res, in)
	for i := 0; i < len(res)/groupSize/2; i++ {
		for j := 0; j < groupSize; j++ {
			a := i*groupSize + j
			b := len(res) - (i+1)*groupSize + j
			res[a], res[b] = res[b], res[a]
		}
	}
	return res
}
