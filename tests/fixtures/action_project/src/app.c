static int clamp(int v, int lo, int hi)
{
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}

int scale(int input, int gain)
{
    return clamp(input * gain, -1000, 1000);
}

int main(void)
{
    return scale(3, 4) > 0 ? 0 : 1;
}
