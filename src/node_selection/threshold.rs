/// Trait for calculating threshold based on total nodes
pub trait ThresholdCalculator {
    /// Calculate the threshold based on the total number of nodes
    fn calculate_threshold(&self, total_nodes: usize) -> usize;

    fn clone_box(&self) -> Box<dyn ThresholdCalculator>;
}

/// Default implementation of ThresholdCalculator
#[derive(Clone)]
pub struct DefaultThresholdCalculator;

impl ThresholdCalculator for DefaultThresholdCalculator {
    fn calculate_threshold(&self, _total_nodes: usize) -> usize {
        _total_nodes / 2 + 1
    }

    fn clone_box(&self) -> Box<dyn ThresholdCalculator> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ThresholdCalculator> {
    fn clone(&self) -> Box<dyn ThresholdCalculator> {
        self.clone_box()
    }
}

