pub fn histogram(values: &[f64], bins: usize) -> Vec<(f64, usize)> {
    // TODO: Use better algorithm.
    // Is there any common and good algorithm?
    let mut bucket: Vec<usize> = vec![0; bins];
    let average = values.iter().collect::<average::Mean>().mean();
    let min = values.iter().collect::<average::Min>().min();
    let max = values
        .iter()
        .collect::<average::Max>()
        .max()
        .min(average * 3.0);
    let step = (max - min) / bins as f64;

    for &v in values {
        let i = std::cmp::min(((v - min) / step) as usize, bins - 1);
        bucket[i] += 1;
    }

    bucket
        .into_iter()
        .enumerate()
        .map(|(i, v)| (step * (i + 1) as f64, v))
        .collect()
}
