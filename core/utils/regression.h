#ifndef BESS_UTILS_REGRESSION_H_
#define BESS_UTILS_REGRESSION_H_

#include <vector>

// Linear regression model (2 variables)
template <class T>
class LinearRegression {
 public:
  LinearRegression() { slope_ = 0.0; }
  void AddData(T x, T y) {
    x_.push_back(x);
    y_.push_back(y);
  }
  void DataCount() { return x_.size(); }

  // Return True if the model is generated successfully
  bool Train() {
    if (x_.size() < 2) {
      return false;
    }

    T sum_x = 0, sum_x2 = 0, sum_y = 0, sum_xy = 0;
    int n = x_.size();
    for (int i = 0; i < n; i++) {
      sum_x += x_[i];
      sum_x2 += x_[i] * x_[i];
      sum_y += y_[i];
      sum_xy += x_[i] * y_[i];
    }

    base_x_ = x_[0];
    base_y_ = y_[0];
    slope_ = double(n * sum_xy - sum_x * sum_y) / double(n * sum_x2 - sum_x * sum_x);
    const_ = (sum_y - slope_ * sum_x) / n;
    return true;
  }
  double GetSlope() { return slope_; }
  // inline T GetY(T x) { return base_y_ + (x - base_x_) * slope_; }
  inline T GetY(T x) { return const_ + x * slope_; }

 private:
  std::vector<T> x_;
  std::vector<T> y_;
  T base_x_;
  T base_y_;
  T const_;
  double slope_;
};

#endif // BESS_UTILS_REGRESSION_H_
