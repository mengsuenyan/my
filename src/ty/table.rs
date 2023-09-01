pub trait TableShow {
    // 列数
    const COLS: usize;

    // 表头
    fn head() -> Vec<String>;

    // 每一列的行内容
    fn cols(&self) -> Vec<(String, Vec<String>)>;

    fn table(&self) -> String {
        let (mut table, mut col_max_size) = (String::new(), vec![]);
        let cols = self.cols();
        cols.iter().for_each(|col| {
            col_max_size.push(
                2 + col
                    .1
                    .iter()
                    .map(|s| s.len())
                    .max()
                    .unwrap_or_default()
                    .max(col.0.len()),
            );
        });

        fn alignment(table: &mut String, size: usize, s: &str) {
            let len = table.len();
            for _ in 0..(size.saturating_sub(s.len()) / 2) {
                table.push(' ');
            }
            table.push_str(s);

            while table.len() < (len + size) {
                table.push(' ');
            }
        }

        fn left(table: &mut String, size: usize, s: &str) {
            let len = table.len();
            table.push(' ');
            table.push_str(s);

            while table.len() < (len + size) {
                table.push(' ');
            }
        }

        for (h, &size) in cols.iter().zip(col_max_size.iter()) {
            alignment(&mut table, size, h.0.as_str());
        }
        table.push('\n');

        let rows = cols.iter().map(|c| c.1.len()).max().unwrap_or_default();

        for idx in 0..rows {
            for (h, &size) in cols.iter().zip(col_max_size.iter()) {
                match h.1.get(idx) {
                    Some(s) => left(&mut table, size, s.as_str()),
                    None => left(&mut table, size, ""),
                }
            }
            table.push('\n');
        }

        if rows > 60 {
            for (h, &size) in cols.iter().zip(col_max_size.iter()) {
                alignment(&mut table, size, h.0.as_str());
            }
        }

        table
    }
}
