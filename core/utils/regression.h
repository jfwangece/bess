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
  bool Train();
  double GetSlope() { return slope_; }
  inline T GetY(T x);

 private:
  std::vector<T> x_;
  std::vector<T> y_;
  T base_x_;
  T base_y_;
  double slope_;
};

#endif // BESS_UTILS_REGRESSION_H_
