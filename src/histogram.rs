pub fn histogram(values: &[f64], bins: usize) -> Vec<(f64, usize)> {
    assert!(bins >= 2);
    let mut bucket: Vec<usize> = vec![0; bins];
    let min = values.iter().collect::<average::Min>().min();
    let max = values.iter().collect::<average::Max>().max();
    let step = (max - min) / (bins - 1) as f64;

    for &v in values {
        let i = std::cmp::min(((v - min) / step).ceil() as usize, bins - 1);
        bucket[i] += 1;
    }

    bucket
        .into_iter()
        .enumerate()
        .map(|(i, v)| (min + step * i as f64, v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_histogram() {
        let values1: [f64; 10] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(
            histogram(&values1, 10),
            vec![
                (1.0, 1),
                (2.0, 1),
                (3.0, 1),
                (4.0, 1),
                (5.0, 1),
                (6.0, 1),
                (7.0, 1),
                (8.0, 1),
                (9.0, 1),
                (10.0, 1)
            ]
        );
        assert_eq!(
            histogram(&values1, 4),
            vec![(1.0, 1), (4.0, 3), (7.0, 3), (10.0, 3)]
        );
        assert_eq!(
            histogram(&values1, 17),
            vec![
                (1.0, 1),
                (1.5625, 0),
                (2.125, 1),
                (2.6875, 0),
                (3.25, 1),
                (3.8125, 0),
                (4.375, 1),
                (4.9375, 0),
                (5.5, 1),
                (6.0625, 1),
                (6.625, 0),
                (7.1875, 1),
                (7.75, 0),
                (8.3125, 1),
                (8.875, 0),
                (9.4375, 1),
                (10.0, 1)
            ]
        );

        let values2: [f64; 10] = [1.0, 1.0, 1.0, 1.0, 1.0, 10.0, 10.0, 10.0, 10.0, 10.0];
        assert_eq!(
            histogram(&values2, 10),
            vec![
                (1.0, 5),
                (2.0, 0),
                (3.0, 0),
                (4.0, 0),
                (5.0, 0),
                (6.0, 0),
                (7.0, 0),
                (8.0, 0),
                (9.0, 0),
                (10.0, 5)
            ]
        );
        assert_eq!(histogram(&values2, 2), vec![(1.0, 5), (10.0, 5)]);
    }
}
