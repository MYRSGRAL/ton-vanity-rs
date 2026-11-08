use std::{
    collections::VecDeque,
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

pub fn number(value: u64) -> String {
    let raw = value.to_string();
    let mut formatted = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, ch) in raw.chars().enumerate() {
        if index > 0 && (raw.len() - index).is_multiple_of(3) {
            formatted.push(' ');
        }
        formatted.push(ch);
    }
    formatted
}

pub fn duration(value: Duration) -> String {
    let seconds = value.as_secs();
    if seconds >= 3600 {
        format!(
            "{}ч {:02}м {:02}с",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        )
    } else if seconds >= 60 {
        format!("{}м {:02}с", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}с")
    }
}

pub struct RateWindow {
    samples: VecDeque<(Instant, u64)>,
}
impl RateWindow {
    pub fn new(started: Instant, initial: u64) -> Self {
        Self {
            samples: VecDeque::from([(started, initial)]),
        }
    }
    pub fn observe(&mut self, at: Instant, count: u64) {
        self.samples.push_back((at, count));
        self.prune(at);
    }
    fn prune(&mut self, now: Instant) {
        while self.samples.len() > 1
            && (now.saturating_duration_since(self.samples[1].0) >= Duration::from_secs(5)
                || self.samples.len() > 1024)
        {
            self.samples.pop_front();
        }
    }
    pub fn rate(&mut self, now: Instant) -> f64 {
        self.prune(now);
        let Some(&(start, first)) = self.samples.front() else {
            return 0.0;
        };
        let Some(&(_, last)) = self.samples.back() else {
            return 0.0;
        };
        let elapsed = now.saturating_duration_since(start).as_secs_f64();
        if elapsed == 0.0 {
            0.0
        } else {
            last.saturating_sub(first) as f64 / elapsed
        }
    }
}

pub fn status(
    phase: &str,
    checked: u64,
    found: usize,
    elapsed: Duration,
    window_rate: f64,
    average: f64,
) -> String {
    let rates = if average > 0.0 && average.is_finite() {
        format!(
            "{}/с за 5с · средняя {}/с",
            number(window_rate.max(0.0).round() as u64),
            number(average.round() as u64)
        )
    } else {
        "скорость: ждём первую пачку".into()
    };
    format!(
        "{phase} · {} · проверено {} · {rates} · находок {found}",
        duration(elapsed),
        number(checked)
    )
}

pub struct Console {
    tty: bool,
    active: bool,
}
impl Default for Console {
    fn default() -> Self {
        Self {
            tty: io::stderr().is_terminal(),
            active: false,
        }
    }
}
impl Console {
    pub fn status(&mut self, text: &str) -> io::Result<()> {
        let mut output = io::stderr().lock();
        if self.tty {
            write!(output, "\r\x1b[2K{text}")?;
            self.active = true;
        } else {
            writeln!(output, "{text}")?;
        }
        output.flush()
    }
    pub fn message(&mut self, text: &str) -> io::Result<()> {
        self.finish()?;
        writeln!(io::stderr(), "{text}")
    }
    pub fn finish(&mut self) -> io::Result<()> {
        if self.active {
            writeln!(io::stderr())?;
            self.active = false;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rolling_rate_averages_batch_boundaries() {
        let started = Instant::now();
        let mut rate = RateWindow::new(started, 0);
        for second in 1..=5 {
            rate.observe(started + Duration::from_secs(second), second * 200_000);
        }
        assert_eq!(rate.rate(started + Duration::from_secs(5)), 200_000.0);
        assert_eq!(rate.rate(started + Duration::from_secs(11)), 0.0);
        assert_eq!(number(20_576_082), "20 576 082");
        assert_eq!(duration(Duration::from_secs(105)), "1м 45с");
    }
    #[test]
    fn status_has_no_hourly_probability_or_infinite_forecast() {
        let line = status("Поиск", 0, 0, Duration::from_secs(2), 0.0, 0.0);
        assert!(!line.contains("inf"));
        assert!(!line.contains("100%"));
        assert!(line.contains("ждём первую пачку"));
    }
}
